#!/usr/bin/env python3
"""
procsnap_viz - render procsnap output as a single self-contained HTML report.

    ./procsnap_viz.py /var/log/procsnap -o report.html          # collector timeline
    ./procsnap_viz.py ./case-1234 -o case.html --since 2h
    ./procsnap_viz.py triage-host/triage.json -o triage.html    # triage report
    ./procsnap_viz.py new/triage.json --compare old/triage.json # with a Changes view

No external assets, no CDN, no fonts fetched, no server: the output opens offline in any
browser and can be attached to a case. Everything taken from the host (command lines,
file names, hostnames) is attacker-controlled, so it is embedded as escaped JSON and
only ever inserted into the page with textContent.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import procsnap as ps  # noqa: E402


SPAN_CAP = 6000


def build(path, since=None, top=60):
    procs = {}            # cmdline -> record
    tree = Counter()      # (pcomm, comm) -> n
    dests = {}            # (comm, ip, port) -> record
    listeners = {}
    findings = {"high": defaultdict(list), "low": defaultdict(list)}
    spans = []            # timeline bars
    conn_pts = []         # timeline dots
    hb = []
    pts = []              # snapshot timestamps (one per heartbeat)
    lspans, cspans = [], []
    lopen, copen = {}, {}
    meta = {"host": "?", "kernel": "?", "interval": None, "t0": None, "t1": None,
            "starts": 0, "exits": 0, "sessions": 0}

    live = {}   # pid -> (ts, comm, cmdline)

    for ev in ps.load(path, since):
        k = ev.get("ev")
        ts = ev.get("ts", 0)
        meta["t0"] = ts if meta["t0"] is None else min(meta["t0"], ts)
        meta["t1"] = ts if meta["t1"] is None else max(meta["t1"], ts)

        if k == "collector_start":
            # close every open span: a new session means the previous one's
            # entities are no longer tracked (see procsnap.reconstruct).
            if pts:
                for pid, v in list(live.items()):
                    spans.append({"comm": v[1], "cmd": v[2], "t0": v[0], "t1": ts,
                                  "pid": pid, "base": v[3], "user": v[4],
                                  "exe": v[5], "del": v[6], "flags": v[7],
                                  "life": None})
                live.clear()
                for key, o in list(lopen.items()):
                    lspans.append({"t0": o[0], "t1": ts, "line": o[1],
                                   "comm": o[2], "flags": o[3]})
                lopen.clear()
                for key, o in list(copen.items()):
                    cspans.append({"t0": o[0], "t1": ts, "line": o[1], "ext": o[2]})
                copen.clear()
            meta["host"] = ev.get("host", "?")
            meta["kernel"] = ev.get("kernel", "?")
            meta["interval"] = ev.get("interval_h") or ev.get("interval")
            meta["sessions"] += 1

        elif k == "heartbeat":
            hb.append([round(ts, 1), ev.get("nproc", 0), ev.get("nconn", 0)])
            pts.append(ts)

        elif k == "proc_start":
            meta["starts"] += 1
            raw = ev.get("cmdline") or "?"
            cmd = raw if len(raw) <= 500 else raw[:500] + " \u2026"
            r = procs.setdefault(cmd, {
                "cmd": cmd, "comm": ev.get("comm"), "exe": ev.get("exe"),
                "n": 0, "first": ts, "last": ts, "users": Counter(),
                "parents": Counter(), "pids": [], "flags": [],
                "deleted": bool(ev.get("exe_deleted")),
            })
            r["n"] += 1
            r["first"] = min(r["first"], ts); r["last"] = max(r["last"], ts)
            r["users"][ev.get("user", "?")] += 1
            if ev.get("pcomm"):
                r["parents"][ev["pcomm"]] += 1
                tree[(ev["pcomm"], ev.get("comm") or "?")] += 1
            if len(r["pids"]) < 12:
                r["pids"].append(ev.get("pid"))
            for t in ps.suspicious(ev):
                if t not in r["flags"]:
                    r["flags"].append(t)
                findings[ps.SEVERITY.get(t, "low")][t].append(
                    {"ts": ts, "pid": ev.get("pid"), "what": cmd,
                     "user": ev.get("user"), "exe": ev.get("exe")})
            live[ev.get("pid")] = (ts, ev.get("comm"), cmd, bool(ev.get("baseline")),
                                   ev.get("user"), ev.get("exe"),
                                   bool(ev.get("exe_deleted")), list(r["flags"]))

        elif k == "exe_deleted":
            raw = ev.get("cmdline") or "?"
            cmd = raw if len(raw) <= 500 else raw[:500] + " \u2026"
            r = procs.get(cmd)
            if r is not None and "exe-deleted" not in r["flags"]:
                r["flags"].append("exe-deleted")
            for t in ps.suspicious(ev):
                findings[ps.SEVERITY.get(t, "low")][t].append(
                    {"ts": ts, "pid": ev.get("pid"), "what": cmd + "   [binary deleted while running]",
                     "user": ev.get("user"), "exe": ev.get("exe")})
            if ev.get("pid") in live:
                v = list(live[ev["pid"]]); v[6] = True; live[ev["pid"]] = tuple(v)

        elif k == "proc_exit":
            meta["exits"] += 1
            st = live.pop(ev.get("pid"), None)
            if st:
                spans.append({"comm": st[1], "cmd": st[2], "t0": st[0], "t1": ts, "pid": ev.get("pid"),
                              "base": st[3], "user": st[4], "exe": st[5],
                              "del": st[6], "flags": st[7],
                              "life": ev.get("lifetime_s")})

        elif k == "listen_close":
            key = (ev.get("proto"), ev.get("laddr"), ev.get("lport"))
            o = lopen.pop(key, None)
            if o:
                lspans.append({"t0": o[0], "t1": ts,
                               "line": o[1], "comm": o[2], "flags": o[3]})

        elif k == "listen_open":
            key = (ev.get("proto"), ev.get("laddr"), ev.get("lport"))
            lopen[key] = (ts,
                          "%-5s %-26s %s" % (ev.get("proto"),
                                             f"{ev.get('laddr')}:{ev.get('lport')}",
                                             ev.get("comm") or "?"),
                          ev.get("comm"), ps.suspicious(ev))
            listeners[key] = {"proto": ev["proto"], "addr": ev["laddr"],
                              "port": ev["lport"], "comm": ev.get("comm"),
                              "user": ev.get("user"), "pid": ev.get("pid"),
                              "ts": ts, "flags": ps.suspicious(ev)}
            for t in ps.suspicious(ev):
                findings[ps.SEVERITY.get(t, "low")][t].append(
                    {"ts": ts, "pid": ev.get("pid"),
                     "what": f"{ev['proto']} {ev['laddr']}:{ev['lport']}  ({ev.get('comm')})",
                     "user": ev.get("user"), "exe": ev.get("exe")})

        elif k == "conn_close":
            key = (ev.get("proto"), ev.get("laddr"), ev.get("lport"),
                   ev.get("raddr"), ev.get("rport"))
            o = copen.pop(key, None)
            if o:
                cspans.append({"t0": o[0], "t1": ts,
                               "line": o[1], "ext": o[2]})

        elif k == "conn_open":
            ip = str(ev.get("raddr") or "?")            # crafted logs: never trust the type
            copen[(ev.get("proto"), ev.get("laddr"), ev.get("lport"),
                   ev.get("raddr"), ev.get("rport"))] = (
                ts,
                "%-5s %-24s-> %-24s %-12s %s" % (
                    ev.get("proto"), f"{ev.get('laddr')}:{ev.get('lport')}",
                    f"{ip}:{ev.get('rport')}", ev.get("state") or "",
                    ev.get("comm") or "?"),
                not ps.is_private(ip))
            comm = str(ev.get("comm") or "?")
            key = (comm, ip, ev.get("rport"))
            d = dests.setdefault(key, {
                "comm": comm, "ip": ip, "port": ev.get("rport"),
                "proto": ev.get("proto"), "n": 0, "first": ts, "last": ts,
                "ext": not ps.is_private(ip), "gaps": [], "cmd": ev.get("cmdline"),
                "dir": ev.get("dir") or "",
            })
            if d["n"]:
                d["gaps"].append(round(ts - d["last"], 1))
            d["n"] += 1
            d["first"] = min(d["first"], ts); d["last"] = max(d["last"], ts)
            conn_pts.append({"t": round(ts, 1), "comm": comm, "ip": ip,
                             "port": ev.get("rport"), "ext": d["ext"]})

    # still-open entities get an open-ended span
    end = meta["t1"] or 0
    for pid, v in live.items():
        spans.append({"comm": v[1], "cmd": v[2], "t0": v[0],
                      "t1": end, "pid": pid, "base": v[3], "user": v[4],
                      "exe": v[5], "del": v[6], "flags": v[7],
                      "life": None, "open": True})
    for key, o in lopen.items():
        lspans.append({"t0": o[0], "t1": end, "line": o[1],
                       "comm": o[2], "flags": o[3], "open": True})
    for key, o in copen.items():
        cspans.append({"t0": o[0], "t1": end, "line": o[1],
                       "ext": o[2], "open": True})

    # ---- rarity + beacon scoring -------------------------------------------
    plist = sorted(procs.values(), key=lambda r: (r["n"], -r["last"]))
    for r in plist:
        r["users"] = dict(r["users"]); r["parents"] = dict(r["parents"].most_common(4))
        r["first"] = round(r["first"], 1); r["last"] = round(r["last"], 1)

    dlist = []
    for d in dests.values():
        g = d["gaps"]
        d["beacon"] = None
        if len(g) >= 3:
            jit = max(g) - min(g)
            avg = sum(g) / len(g)
            if avg > 0 and jit <= max(2.0, avg * 0.35):
                d["beacon"] = {"avg": round(avg, 1), "jitter": round(jit, 1),
                               "hits": len(g) + 1}
        d.pop("gaps")
        d["first"] = round(d["first"], 1); d["last"] = round(d["last"], 1)
        dlist.append(d)
    dlist.sort(key=lambda d: (not d["ext"], -d["n"]))

    # ---- graph -------------------------------------------------------------
    nodes, index, links = [], {}, []

    def node(nid, label, kind, meta_=None):
        if nid not in index:
            index[nid] = len(nodes)
            nodes.append({"id": nid, "label": label, "kind": kind,
                          "w": 1, "meta": meta_ or {}})
        return index[nid]

    hostid = node("host:" + meta["host"], meta["host"], "host")
    for (par, chi), n in tree.most_common(top):
        a = node("p:" + par, par, "proc"); b = node("p:" + chi, chi, "proc")
        nodes[a]["w"] += n; nodes[b]["w"] += n
        links.append({"s": a, "t": b, "n": n, "kind": "spawn"})
    for d in dlist[:top]:
        if not d["ext"]:
            continue
        a = node("p:" + d["comm"], d["comm"], "proc")
        b = node("ip:" + d["ip"], d["ip"], "ext")
        nodes[b]["w"] += d["n"]
        links.append({"s": a, "t": b, "n": d["n"], "kind": "net",
                      "port": d["port"], "beacon": bool(d["beacon"])})
    for l in listeners.values():
        a = node("p:" + (l["comm"] or "?"), l["comm"] or "?", "proc")
        b = node("l:%s:%s" % (l["addr"], l["port"]), ":%s" % l["port"], "listen")
        links.append({"s": a, "t": b, "n": 1, "kind": "listen"})
    # attach orphan process nodes to the host so the graph stays connected
    linked = {l["s"] for l in links} | {l["t"] for l in links}
    for i, nd in enumerate(nodes):
        if nd["kind"] == "proc" and i not in linked:
            links.append({"s": hostid, "t": i, "n": 1, "kind": "spawn"})
    for nd in nodes:
        if nd["kind"] == "proc":
            for r in plist:
                if r["comm"] == nd["label"]:
                    nd["meta"] = {"flags": r["flags"], "n": r["n"], "exe": r["exe"]}
                    break

    fin = {lvl: {t: v[:40] for t, v in d.items()} for lvl, d in findings.items()}
    return {
        "meta": meta,
        "procs": plist[:400],
        "dests": dlist[:200],
        "listeners": sorted(listeners.values(), key=lambda l: l["port"]),
        "findings": fin,
        "graph": {"nodes": nodes, "links": links},
        "spans": sorted(spans, key=lambda s: s["t0"])[:SPAN_CAP],
        "truncated": {"spans": max(0, len(spans) - SPAN_CAP),
                      "procs": max(0, len(plist) - 400),
                      "conns": max(0, len(conn_pts) - 2000)},
        "pts": pts,
        "lspans": lspans,
        "cspans": cspans,
        "conns": conn_pts[:2000],
        "hb": hb,
    }


def safe_json(obj) -> str:
    """JSON that cannot break out of a <script> block.

    json.dumps leaves '<', '>' and '&' alone, so a process whose command line
    contains '</script><script>...' would otherwise inject live script into the
    report an analyst opens. Escaping them as \\u003c etc. keeps the JSON valid
    and inert.
    """
    return (json.dumps(obj, separators=(",", ":"), default=str)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def fill(template: str, data, **kw) -> str:
    """Substitute placeholders. Data goes in LAST so its content is never re-scanned."""
    values = {k: html.escape(str(v)) for k, v in kw.items()}
    values["DATA"] = safe_json(data)
    # one pass over the template only: substituted text (a hostname containing
    # "__DATA__", say) is never scanned again
    return re.sub(r"__([A-Z]+)__", lambda m: values.get(m.group(1), m.group(0)), template)


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  --paper:#f6f7f9; --surface:#fff; --surface-2:#eef1f4; --surface-3:#e4e9ee;
  --ink:#131920; --ink-2:#48545f; --ink-3:#7a8792;
  --line:#d7dee5; --line-2:#c3ccd5;
  --hi:#b3271f; --hi-soft:#fbeae8;
  --warn:#8a5d0b; --warn-soft:#fbf2de;
  --ok:#1f6b4d; --ok-soft:#e3f1ea;
  --net:#1d5f8a; --f:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --m:ui-monospace,"SFMono-Regular","Cascadia Mono","JetBrains Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --paper:#0c1014; --surface:#131a21; --surface-2:#1a232b; --surface-3:#212c35;
  --ink:#e6ecf1; --ink-2:#9daab6; --ink-3:#6d7d8a;
  --line:#25303a; --line-2:#33414d;
  --hi:#ff6f61; --hi-soft:#2b1512; --warn:#e0a94a; --warn-soft:#2a2113;
  --ok:#4fb98a; --ok-soft:#122a21; --net:#5aa6d6;
}}
:root[data-theme="dark"]{
  --paper:#0c1014; --surface:#131a21; --surface-2:#1a232b; --surface-3:#212c35;
  --ink:#e6ecf1; --ink-2:#9daab6; --ink-3:#6d7d8a;
  --line:#25303a; --line-2:#33414d;
  --hi:#ff6f61; --hi-soft:#2b1512; --warn:#e0a94a; --warn-soft:#2a2113;
  --ok:#4fb98a; --ok-soft:#122a21; --net:#5aa6d6;
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--f);
  font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
h1,h2,h3{margin:0;font-weight:700;letter-spacing:-.02em;text-wrap:balance}
.wrap{max-width:1400px;margin:0 auto;padding:0 22px}

/* header */
.top{background:var(--surface);border-bottom:1px solid var(--line)}
.top-in{display:flex;flex-wrap:wrap;gap:24px;align-items:flex-end;
  justify-content:space-between;padding:26px 0 20px}
.eyebrow{font-family:var(--m);font-size:10px;letter-spacing:.18em;
  text-transform:uppercase;color:var(--hi);display:flex;align-items:center;gap:8px}
.eyebrow::before{content:"";width:18px;height:2px;background:var(--hi)}
h1{font-size:clamp(22px,3vw,31px);margin:9px 0 0}
.tiles{display:flex;flex-wrap:wrap;gap:9px}
.tile{background:var(--surface-2);border:1px solid var(--line);border-radius:3px;
  padding:8px 13px;min-width:92px}
.tile .k{font-family:var(--m);font-size:9px;letter-spacing:.13em;
  text-transform:uppercase;color:var(--ink-3)}
.tile .v{font-family:var(--m);font-size:17px;font-weight:700;
  font-variant-numeric:tabular-nums;margin-top:2px}
.tile.bad .v{color:var(--hi)}

/* tabs */
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--line);
  background:var(--surface);position:sticky;top:0;z-index:20}
.tabs .wrap{display:flex;gap:2px}
.tab{font-family:var(--m);font-size:11px;letter-spacing:.09em;text-transform:uppercase;
  background:none;border:0;border-bottom:2px solid transparent;color:var(--ink-3);
  padding:12px 15px;cursor:pointer}
.tab:hover{color:var(--ink)}
.tab.on{color:var(--hi);border-bottom-color:var(--hi)}
.tab:focus-visible{outline:2px solid var(--hi);outline-offset:-2px}
.pane{display:none;padding:26px 0 70px}
.pane.on{display:block}

/* findings */
.sect{font-family:var(--m);font-size:10px;letter-spacing:.15em;text-transform:uppercase;
  color:var(--ink-3);padding-bottom:9px;border-bottom:1px solid var(--line);
  margin:0 0 14px;display:flex;justify-content:space-between;align-items:baseline}
.fgroup{border:1px solid var(--line);border-left:3px solid var(--hi);border-radius:2px;
  background:var(--surface);margin-bottom:12px;overflow:hidden}
.fgroup.low{border-left-color:var(--warn)}
.fhead{display:flex;justify-content:space-between;align-items:center;gap:12px;
  padding:11px 15px;background:var(--surface-2);cursor:pointer}
.fhead h3{font-size:13.5px;color:var(--hi)}
.fgroup.low .fhead h3{color:var(--warn)}
.cnt{font-family:var(--m);font-size:10px;color:var(--ink-3)}
.fbody{padding:4px 15px 12px}
.frow{display:grid;grid-template-columns:130px 62px 1fr;gap:11px;padding:6px 0;
  border-bottom:1px dotted var(--line);font-family:var(--m);font-size:11.5px}
.frow:last-child{border-bottom:0}
.frow .t{color:var(--ink-3)}
.frow .w{color:var(--ink);overflow-wrap:anywhere}
.empty{color:var(--ink-3);font-family:var(--m);font-size:12px;padding:8px 0}

/* tables */
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:2px;
  background:var(--surface);margin-bottom:22px}
table{border-collapse:collapse;width:100%;min-width:640px}
th{font-family:var(--m);font-size:9.5px;letter-spacing:.13em;text-transform:uppercase;
  color:var(--ink-3);text-align:left;font-weight:500;padding:9px 13px;
  border-bottom:1px solid var(--line);background:var(--surface-2);
  position:sticky;top:41px;cursor:pointer;white-space:nowrap}
th:hover{color:var(--ink)}
td{padding:8px 13px;border-bottom:1px solid var(--line);font-size:12.5px;
  vertical-align:top;color:var(--ink-2);font-family:var(--m)}
td.cmd{color:var(--ink);overflow-wrap:anywhere;max-width:600px}
tr:last-child td{border-bottom:0}
tr.flag td{background:var(--hi-soft)}
.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{font-family:var(--m);font-size:9px;letter-spacing:.07em;text-transform:uppercase;
  padding:2px 6px;border-radius:2px;background:var(--surface-3);color:var(--ink-2);
  display:inline-block;margin-right:3px;white-space:nowrap}
.pill.hi{background:var(--hi-soft);color:var(--hi)}
.pill.lo{background:var(--warn-soft);color:var(--warn)}
.pill.ext{background:var(--hi-soft);color:var(--hi)}
.pill.bea{background:var(--warn-soft);color:var(--warn)}

/* graph */
.gwrap{display:grid;grid-template-columns:minmax(0,1fr) 290px;gap:16px}
@media(max-width:900px){.gwrap{grid-template-columns:1fr}}
.gbox{background:var(--surface);border:1px solid var(--line);border-radius:2px;
  position:relative;overflow:hidden}
canvas{display:block;width:100%;height:620px;cursor:grab}
canvas.drag{cursor:grabbing}
.legend{position:absolute;left:11px;bottom:11px;display:flex;flex-direction:column;
  gap:5px;font-family:var(--m);font-size:10px;color:var(--ink-2);
  background:color-mix(in srgb,var(--surface) 88%,transparent);
  padding:8px 10px;border:1px solid var(--line);border-radius:2px}
.legend i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.side{background:var(--surface);border:1px solid var(--line);border-radius:2px;
  padding:15px;align-self:start;position:sticky;top:56px}
.side h3{font-size:13px;margin-bottom:9px}
.side dl{margin:0;font-family:var(--m);font-size:11px}
.side dt{color:var(--ink-3);margin-top:8px;font-size:9.5px;letter-spacing:.1em;
  text-transform:uppercase}
.side dd{margin:2px 0 0;color:var(--ink);overflow-wrap:anywhere}
.hint{color:var(--ink-3);font-family:var(--m);font-size:11px;line-height:1.6}

/* snapshots */
.snapwrap{display:grid;grid-template-columns:236px minmax(0,1fr);gap:16px}
@media(max-width:900px){.snapwrap{grid-template-columns:1fr}}
.picker{background:var(--surface);border:1px solid var(--line);border-radius:2px;
  align-self:start;position:sticky;top:56px;overflow:hidden}
.pk-head{display:flex;justify-content:space-between;align-items:center;gap:8px;
  padding:9px 11px;border-bottom:1px solid var(--line);background:var(--surface-2);
  font-family:var(--m);font-size:10px;letter-spacing:.09em;text-transform:uppercase;
  color:var(--ink-3)}
.mini{font-family:var(--m);font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;
  background:none;border:1px solid var(--line-2);color:var(--ink-2);padding:2px 7px;
  border-radius:2px;cursor:pointer}
.mini:hover{background:var(--ink);color:var(--surface);border-color:var(--ink)}
.mini:focus-visible{outline:2px solid var(--hi);outline-offset:1px}
.pk-list{max-height:460px;overflow-y:auto}
.pk{display:grid;grid-template-columns:34px 1fr;gap:8px;padding:6px 11px;
  font-family:var(--m);font-size:11px;cursor:pointer;border-bottom:1px dotted var(--line);
  color:var(--ink-2)}
.pk:hover{background:var(--surface-2);color:var(--ink)}
.pk.on{background:var(--hi-soft);color:var(--hi)}
.pk .i{color:var(--ink-3);font-variant-numeric:tabular-nums}
.pk.on .i{color:var(--hi)}
.picker .hint{padding:9px 11px 11px;margin:0;border-top:1px solid var(--line)}
.snapout{min-width:0}
.dgroup{margin-bottom:22px}
.dhead{font-family:var(--m);font-size:10px;letter-spacing:.14em;text-transform:uppercase;
  color:var(--ink-3);padding-bottom:8px;border-bottom:1px solid var(--line);
  margin-bottom:9px;display:flex;justify-content:space-between;gap:12px}
.dhead b{color:var(--ink);font-weight:500}
.dl{font-family:var(--m);font-size:11.5px;background:var(--surface);
  border:1px solid var(--line);border-radius:2px;overflow-x:auto}
.dl div{padding:3px 11px;white-space:pre;border-bottom:1px dotted var(--line)}
.dl div:last-child{border-bottom:0}
.dl .add{background:var(--ok-soft);color:var(--ok)}
.dl .rem{background:var(--hi-soft);color:var(--hi)}
.dl .mat{color:var(--ink-2)}
.dl .mat b{color:var(--hi);font-weight:700}
.dl .same{color:var(--ink-2)}
.dl .exe{color:var(--ink-3);padding-left:26px;background:none}
.dl .none{color:var(--ink-3);font-style:italic}
.sumline{font-family:var(--m);font-size:11.5px;color:var(--ink-2);
  background:var(--surface-2);border:1px solid var(--line);border-radius:2px;
  padding:10px 13px;margin-bottom:18px}
.sumline b{color:var(--hi)}

/* timeline */
.tl{background:var(--surface);border:1px solid var(--line);border-radius:2px;
  overflow-x:auto}
.tl svg{display:block}
.ctl{display:flex;flex-wrap:wrap;gap:9px;align-items:center;margin-bottom:13px}
.ctl input,.ctl select{font-family:var(--m);font-size:11.5px;padding:6px 9px;
  background:var(--surface);color:var(--ink);border:1px solid var(--line-2);
  border-radius:2px}
.ctl input:focus-visible,.ctl select:focus-visible{outline:2px solid var(--hi);
  outline-offset:1px}
.ctl label{font-family:var(--m);font-size:10px;letter-spacing:.1em;
  text-transform:uppercase;color:var(--ink-3)}
.foot{border-top:1px solid var(--line);padding:18px 0 40px;font-family:var(--m);
  font-size:10.5px;color:var(--ink-3);display:flex;flex-wrap:wrap;gap:14px;
  justify-content:space-between}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
</style></head><body>

<header class="top"><div class="wrap top-in">
  <div>
    <div class="eyebrow">RedSide Security · ProcSnap timeline report</div>
    <h1 id="hostTitle">host</h1>
  </div>
  <div class="tiles" id="tiles"></div>
</div></header>

<nav class="tabs"><div class="wrap">
  <button class="tab on" data-p="findings">Findings</button>
  <button class="tab" data-p="snaps">Snapshots</button>
  <button class="tab" data-p="graph">Graph</button>
  <button class="tab" data-p="timeline">Timeline</button>
  <button class="tab" data-p="procs">Processes</button>
  <button class="tab" data-p="net">Network</button>
</div></nav>

<div class="wrap">
  <section class="pane on" id="p-findings"></section>

  <section class="pane" id="p-snaps">
    <div class="sect"><span>Point-in-time state — pick one to view, two or more to compare</span>
      <span class="cnt" id="scount"></span></div>
    <div class="snapwrap">
      <aside class="picker">
        <div class="pk-head">
          <span id="pksel">0 selected</span>
          <button class="mini" id="pkclear">clear</button>
        </div>
        <div class="pk-list" id="pklist"></div>
        <p class="hint">Shift-click a second row to select the range between them.</p>
      </aside>
      <div class="snapout" id="snapout"></div>
    </div>
  </section>

  <section class="pane" id="p-graph">
    <div class="sect"><span>Host → process → destination</span>
      <span class="cnt" id="gcount"></span></div>
    <div class="gwrap">
      <div class="gbox">
        <canvas id="cv"></canvas>
        <div class="legend">
          <span><i style="background:var(--ink-2)"></i>process</span>
          <span><i style="background:var(--hi)"></i>external IP</span>
          <span><i style="background:var(--net)"></i>listening port</span>
          <span><i style="background:var(--warn)"></i>flagged process</span>
        </div>
      </div>
      <aside class="side" id="side">
        <h3>Node detail</h3>
        <p class="hint">Click a node to inspect it. Drag to reposition,
          scroll to zoom.</p>
      </aside>
    </div>
  </section>

  <section class="pane" id="p-timeline">
    <div class="sect"><span>Process lifetimes and connections</span>
      <span class="cnt" id="tlcount"></span></div>
    <div class="ctl">
      <label for="tlf">filter</label>
      <input id="tlf" placeholder="comm or cmdline substring" size="26">
      <label for="tlb">baseline</label>
      <select id="tlb">
        <option value="0">hide pre-existing</option>
        <option value="1">show all</option>
      </select>
    </div>
    <div class="tl" id="tl"></div>
  </section>

  <section class="pane" id="p-procs">
    <div class="sect"><span>Executions, rarest first</span>
      <span class="cnt">click a header to sort</span></div>
    <div class="ctl">
      <label for="pf">filter</label>
      <input id="pf" placeholder="comm, cmdline or exe" size="30">
    </div>
    <div class="tw"><table id="ptab"></table></div>
  </section>

  <section class="pane" id="p-net">
    <div class="sect"><span>Connections and listeners</span>
      <span class="cnt">external and beaconing first</span></div>
    <div class="tw"><table id="dtab"></table></div>
    <div class="sect"><span>Listening sockets</span><span class="cnt"></span></div>
    <div class="tw"><table id="ltab"></table></div>
  </section>

  <div class="foot">
    <span id="footmeta"></span>
    <span>procsnap __VERSION__ · generated from JSONL event log</span>
  </div>
</div>

<script id="data" type="application/json">__DATA__</script>
<script>
var D = JSON.parse(document.getElementById("data").textContent);
var T0 = D.meta.t0 || 0, T1 = D.meta.t1 || 1;
function ts(t){ var d=new Date(t*1000);
  return d.toLocaleString(undefined,{month:"2-digit",day:"2-digit",
    hour:"2-digit",minute:"2-digit",second:"2-digit"}); }
function el(t,c,x){ var e=document.createElement(t); if(c)e.className=c;
  if(x!==undefined)e.textContent=x; return e; }

/* ---------- header ---------- */
document.getElementById("hostTitle").textContent = D.meta.host;
var nHigh=0, nLow=0;
for(var k in D.findings.high) nHigh += D.findings.high[k].length;
for(var k in D.findings.low)  nLow  += D.findings.low[k].length;
var extN = D.dests.filter(function(d){return d.ext}).length;
var beaN = D.dests.filter(function(d){return d.beacon}).length;
[["window", (T1-T0)>=3600 ? ((T1-T0)/3600).toFixed(1)+"h" : (T1-T0)>=60 ? Math.round((T1-T0)/60)+"m" : Math.round(T1-T0)+"s"],
 ["interval", String(D.meta.interval||"?")],
 ["exec", D.meta.starts],
 ["listeners", D.listeners.length],
 ["ext dests", extN],
 ["beacons", beaN],
 ["high", nHigh]].forEach(function(p,i){
  var t=el("div","tile"+((i>=5&&p[1]>0)?" bad":""));
  t.appendChild(el("div","k",p[0])); t.appendChild(el("div","v",String(p[1])));
  document.getElementById("tiles").appendChild(t);
});
document.getElementById("footmeta").textContent =
  D.meta.kernel+" · "+ts(T0)+" → "+ts(T1)+" · "+D.meta.sessions+" collector session(s)";

/* ---------- tabs ---------- */
var drawnGraph=false;
document.querySelectorAll(".tab").forEach(function(b){
  b.addEventListener("click",function(){
    document.querySelectorAll(".tab").forEach(function(x){x.classList.remove("on")});
    document.querySelectorAll(".pane").forEach(function(x){x.classList.remove("on")});
    b.classList.add("on");
    document.getElementById("p-"+b.dataset.p).classList.add("on");
    if(b.dataset.p==="graph"){ sizeCanvas(); if(!drawnGraph){ runSim(); drawnGraph=true; } draw(); }
    if(b.dataset.p==="timeline") drawTL();
    if(b.dataset.p==="snaps") drawSnaps();
  });
});

/* ---------- findings ---------- */
(function(){
  var host=document.getElementById("p-findings");
  [["high","Act on these","",""],["low","Context only — expect benign hits","low",""]]
  .forEach(function(lv){
    var groups=D.findings[lv[0]], keys=Object.keys(groups);
    var s=el("div","sect"); s.appendChild(el("span",null,lv[1]));
    var tot=0; keys.forEach(function(k){tot+=groups[k].length});
    s.appendChild(el("span","cnt",tot+" event"+(tot===1?"":"s")));
    host.appendChild(s);
    if(!keys.length){ host.appendChild(el("div","empty","No "+lv[0]+"-severity flags in this window.")); return; }
    keys.sort(function(a,b){return groups[b].length-groups[a].length});
    keys.forEach(function(k){
      var g=el("div","fgroup"+(lv[2]?" "+lv[2]:""));
      var h=el("div","fhead"); h.appendChild(el("h3",null,k));
      h.appendChild(el("span","cnt",groups[k].length+" ▾"));
      var body=el("div","fbody");
      var seen={};
      groups[k].forEach(function(f){
        if(seen[f.what]) return; seen[f.what]=1;
        var r=el("div","frow");
        r.appendChild(el("span","t",ts(f.ts)));
        r.appendChild(el("span","t","pid "+f.pid));
        r.appendChild(el("span","w",f.what));
        body.appendChild(r);
      });
      h.addEventListener("click",function(){
        var on=body.style.display!=="none";
        body.style.display=on?"none":"";
        h.lastChild.textContent=groups[k].length+(on?" ▸":" ▾");
      });
      g.appendChild(h); g.appendChild(body); host.appendChild(g);
    });
  });
})();

/* ---------- tables ---------- */
function table(node, cols, rows, rowFlag){
  node.innerHTML="";
  var thead=el("thead"), tr=el("tr");
  cols.forEach(function(c,i){
    var th=el("th",null,c.h);
    th.addEventListener("click",function(){
      var dir = th.dataset.d==="1" ? -1 : 1; th.dataset.d = dir===1?"1":"";
      rows.sort(function(a,b){
        var x=c.v(a), y=c.v(b);
        if(typeof x==="number"&&typeof y==="number") return (x-y)*dir;
        return String(x).localeCompare(String(y))*dir;
      });
      body(); });
    tr.appendChild(th);
  });
  thead.appendChild(tr); node.appendChild(thead);
  var tb=el("tbody"); node.appendChild(tb);
  function body(){
    tb.innerHTML="";
    rows.forEach(function(r){
      var t=el("tr"); if(rowFlag&&rowFlag(r)) t.className="flag";
      cols.forEach(function(c){
        var td=el("td",c.cls||null);
        var v=c.r?c.r(r):c.v(r);
        if(v&&v.nodeType) td.appendChild(v); else td.textContent=String(v===undefined?"":v);
        t.appendChild(td);
      });
      tb.appendChild(t);
    });
  }
  body(); return body;
}
function pills(list, cls){
  var f=document.createDocumentFragment();
  (list||[]).forEach(function(x){ f.appendChild(el("span","pill "+cls,x)); });
  return f;
}

var procRows=D.procs.slice();
var redrawP=table(document.getElementById("ptab"),[
  {h:"n",v:function(r){return r.n},cls:"num"},
  {h:"first seen",v:function(r){return r.first},r:function(r){return ts(r.first)}},
  {h:"comm",v:function(r){return r.comm||""}},
  {h:"user",v:function(r){return Object.keys(r.users).join(",")}},
  {h:"parents",v:function(r){return Object.keys(r.parents).join(",")}},
  {h:"flags",v:function(r){return r.flags.join(",")},
   r:function(r){return pills(r.flags,"hi")}},
  {h:"cmdline",v:function(r){return r.cmd},cls:"cmd"}
], procRows, function(r){return r.flags.length});
document.getElementById("pf").addEventListener("input",function(e){
  var q=e.target.value.toLowerCase();
  procRows.length=0;
  D.procs.forEach(function(r){
    if(!q||(r.cmd+" "+(r.comm||"")+" "+(r.exe||"")).toLowerCase().indexOf(q)>=0)
      procRows.push(r);
  });
  redrawP();
});

table(document.getElementById("dtab"),[
  {h:"n",v:function(r){return r.n},cls:"num"},
  {h:"process",v:function(r){return r.comm}},
  {h:"direction",v:function(r){return r.dir||""}},
  {h:"remote",v:function(r){return r.ip}},
  {h:"port",v:function(r){return r.port},cls:"num"},
  {h:"scope",v:function(r){return r.ext?"external":"internal"},
   r:function(r){return r.ext?pills(["external"],"ext"):pills(["internal"],"")}},
  {h:"beacon",v:function(r){return r.beacon?r.beacon.avg:0},
   r:function(r){return r.beacon?pills([r.beacon.avg+"s ±"+r.beacon.jitter],"bea"):document.createTextNode("")}},
  {h:"geo / intel",v:function(r){return r.geo||""}},
  {h:"first",v:function(r){return r.first},r:function(r){return ts(r.first)}},
  {h:"last",v:function(r){return r.last},r:function(r){return ts(r.last)}}
], D.dests.slice(), function(r){return r.ext||r.beacon});

table(document.getElementById("ltab"),[
  {h:"proto",v:function(r){return r.proto}},
  {h:"bind",v:function(r){return r.addr}},
  {h:"port",v:function(r){return r.port},cls:"num"},
  {h:"process",v:function(r){return r.comm||"?"}},
  {h:"user",v:function(r){return r.user||"?"}},
  {h:"pid",v:function(r){return r.pid||""},cls:"num"},
  {h:"flags",v:function(r){return (r.flags||[]).join(",")},
   r:function(r){return pills(r.flags,"lo")}}
], D.listeners.slice(), function(r){return (r.flags||[]).length});

/* ---------- graph ---------- */
var cv=document.getElementById("cv"), cx=cv.getContext("2d");
var N=D.graph.nodes, L=D.graph.links, sel=null;
var view={x:0,y:0,k:1};
document.getElementById("gcount").textContent=N.length+" nodes · "+L.length+" edges";
N.forEach(function(n,i){
  var a=i*2.399963;                       // deterministic golden-angle spiral
  n.x=Math.cos(a)*(30+i*7); n.y=Math.sin(a)*(30+i*7); n.vx=0; n.vy=0;
  n.r=n.kind==="host"?16:Math.min(19,5+Math.sqrt(n.w)*1.7);
  n.flag=(n.meta&&n.meta.flags&&n.meta.flags.length)?1:0;
});
function sizeCanvas(){
  var r=cv.getBoundingClientRect(), dpr=window.devicePixelRatio||1;
  cv.width=r.width*dpr; cv.height=r.height*dpr;
  cx.setTransform(dpr,0,0,dpr,0,0);
}
function runSim(){
  for(var it=0; it<320; it++){
    for(var i=0;i<N.length;i++){
      var a=N[i];
      for(var j=i+1;j<N.length;j++){
        var b=N[j], dx=b.x-a.x, dy=b.y-a.y, d2=dx*dx+dy*dy||0.01;
        if(d2>360000) continue;
        var f=2600/d2, d=Math.sqrt(d2);
        a.vx-=dx/d*f; a.vy-=dy/d*f; b.vx+=dx/d*f; b.vy+=dy/d*f;
      }
    }
    L.forEach(function(l){
      var a=N[l.s], b=N[l.t], dx=b.x-a.x, dy=b.y-a.y;
      var d=Math.sqrt(dx*dx+dy*dy)||0.01, want=l.kind==="net"?135:95;
      var f=(d-want)*0.012;
      a.vx+=dx/d*f; a.vy+=dy/d*f; b.vx-=dx/d*f; b.vy-=dy/d*f;
    });
    N.forEach(function(n){
      n.vx-=n.x*0.0022; n.vy-=n.y*0.0022;
      n.x+=n.vx*=0.82; n.y+=n.vy*=0.82;
    });
  }
  var xs=N.map(function(n){return n.x}), ys=N.map(function(n){return n.y});
  var w=cv.getBoundingClientRect().width||900, h=620;
  var sx=(Math.max.apply(null,xs)-Math.min.apply(null,xs))||1;
  var sy=(Math.max.apply(null,ys)-Math.min.apply(null,ys))||1;
  view.k=Math.min(w/(sx+150), h/(sy+150), 1.6);
  view.x=w/2; view.y=h/2;
}
function css(v){ return getComputedStyle(document.documentElement).getPropertyValue(v).trim(); }
function draw(){
  var w=cv.getBoundingClientRect().width, h=cv.getBoundingClientRect().height;
  cx.clearRect(0,0,w,h);
  var C={ink:css("--ink"),ink2:css("--ink-2"),ink3:css("--ink-3"),
         hi:css("--hi"),net:css("--net"),warn:css("--warn"),line:css("--line-2"),
         surf:css("--surface")};
  function px(n){return n.x*view.k+view.x} function py(n){return n.y*view.k+view.y}
  L.forEach(function(l){
    var a=N[l.s], b=N[l.t];
    cx.beginPath(); cx.moveTo(px(a),py(a)); cx.lineTo(px(b),py(b));
    cx.strokeStyle = l.kind==="net" ? (l.beacon?C.warn:C.hi) :
                     l.kind==="listen" ? C.net : C.line;
    cx.globalAlpha = (sel===null||l.s===sel||l.t===sel)?0.75:0.13;
    cx.lineWidth = Math.min(3.5, 0.6+Math.log(1+l.n)*0.7);
    if(l.kind==="net") cx.setLineDash([4,3]); else cx.setLineDash([]);
    cx.stroke();
  });
  cx.setLineDash([]); cx.globalAlpha=1;
  N.forEach(function(n,i){
    var col = n.kind==="host"?C.ink : n.kind==="ext"?C.hi :
              n.kind==="listen"?C.net : n.flag?C.warn:C.ink2;
    cx.globalAlpha=(sel===null||sel===i)?1:0.3;
    cx.beginPath(); cx.arc(px(n),py(n),n.r*Math.max(.6,view.k),0,6.2832);
    cx.fillStyle=col; cx.fill();
    if(sel===i){ cx.lineWidth=2.5; cx.strokeStyle=C.ink; cx.stroke(); }
    if(view.k>0.45||n.r>9||sel===i){
      cx.font='500 11px '+css("--m");
      cx.fillStyle=C.ink; cx.textAlign="center";
      cx.strokeStyle=C.surf; cx.lineWidth=3;
      var ly=py(n)+n.r*Math.max(.6,view.k)+12;
      cx.strokeText(n.label,px(n),ly); cx.fillText(n.label,px(n),ly);
    }
  });
  cx.globalAlpha=1;
}
function hit(mx,my){
  for(var i=N.length-1;i>=0;i--){
    var n=N[i], dx=mx-(n.x*view.k+view.x), dy=my-(n.y*view.k+view.y);
    if(dx*dx+dy*dy < Math.pow(n.r*Math.max(.6,view.k)+4,2)) return i;
  }
  return null;
}
function showNode(i){
  var s=document.getElementById("side"); s.innerHTML="";
  if(i===null){ s.appendChild(el("h3",null,"Node detail"));
    s.appendChild(el("p","hint","Click a node to inspect it. Drag to reposition, scroll to zoom."));
    return; }
  var n=N[i];
  s.appendChild(el("h3",null,n.label));
  var dl=el("dl");
  function row(k,v){ dl.appendChild(el("dt",null,k)); dl.appendChild(el("dd",null,v)); }
  row("kind", n.kind==="ext"?"external destination":n.kind);
  if(n.meta&&n.meta.exe) row("exe", n.meta.exe);
  if(n.meta&&n.meta.n) row("executions", String(n.meta.n));
  if(n.meta&&n.meta.flags&&n.meta.flags.length) row("flags", n.meta.flags.join(", "));
  var ins=L.filter(function(l){return l.t===i}), outs=L.filter(function(l){return l.s===i});
  if(ins.length) row("parents / sources", ins.map(function(l){return N[l.s].label+" ("+l.n+")"}).join(", "));
  if(outs.length) row("children / destinations", outs.map(function(l){
    return N[l.t].label+(l.port?":"+l.port:"")+" ("+l.n+")"+(l.beacon?" beacon":"")}).join(", "));
  if(n.kind==="ext"){
    var ds=D.dests.filter(function(d){return d.ip===n.label});
    row("ports", ds.map(function(d){return d.port}).join(", "));
    var b=ds.filter(function(d){return d.beacon});
    if(b.length) row("beacon", b.map(function(d){return d.beacon.avg+"s ±"+d.beacon.jitter+" ("+d.beacon.hits+" hits)"}).join(", "));
  }
  s.appendChild(dl);
}
var drag=null, moved=false;
cv.addEventListener("mousedown",function(e){
  var r=cv.getBoundingClientRect(), mx=e.clientX-r.left, my=e.clientY-r.top;
  var i=hit(mx,my); moved=false;
  drag={i:i,mx:mx,my:my}; cv.classList.add("drag");
});
window.addEventListener("mousemove",function(e){
  if(!drag) return;
  var r=cv.getBoundingClientRect(), mx=e.clientX-r.left, my=e.clientY-r.top;
  var dx=mx-drag.mx, dy=my-drag.my;
  if(Math.abs(dx)+Math.abs(dy)>3) moved=true;
  if(drag.i===null){ view.x+=dx; view.y+=dy; }
  else { N[drag.i].x+=dx/view.k; N[drag.i].y+=dy/view.k; }
  drag.mx=mx; drag.my=my; draw();
});
window.addEventListener("mouseup",function(){
  if(drag&&!moved){ sel=(sel===drag.i)?null:drag.i; showNode(sel); draw(); }
  drag=null; cv.classList.remove("drag");
});
cv.addEventListener("wheel",function(e){
  e.preventDefault();
  var r=cv.getBoundingClientRect(), mx=e.clientX-r.left, my=e.clientY-r.top;
  var f=e.deltaY<0?1.12:0.89, k2=Math.max(0.15,Math.min(4,view.k*f));
  view.x=mx-(mx-view.x)*(k2/view.k); view.y=my-(my-view.y)*(k2/view.k);
  view.k=k2; draw();
},{passive:false});
window.addEventListener("resize",function(){ sizeCanvas(); draw(); if(document.getElementById("p-timeline").classList.contains("on")) drawTL(); });


/* ---------- snapshots: point-in-time state + N-way compare ---------- */
var PTS = D.pts || [], picked = [], lastClick = null;
var SEC = [
  {k:"PROCESSES", src:function(){return D.spans},
   line:function(s){ return (s.user||"?").padEnd(12)+" "+s.cmd; },
   extra:function(s){ return s.exe ? ("exe="+s.exe+(s["del"]?"   [DELETED]":"")) : null; }},
  {k:"LISTENERS", src:function(){return D.lspans}, line:function(s){return s.line}},
  {k:"CONNECTIONS", src:function(){return D.cspans}, line:function(s){return s.line}}
];
function stateAt(sec, t){
  var m = {}, E = 1e-6;
  sec.src().forEach(function(s){
    if(s.t0 > t + E) return;
    // a closed span's end is exclusive: at the snapshot that recorded the exit,
    // the entity is already gone. An open span runs to the end of the log.
    if(s.open ? (t <= s.t1 + E) : (t < s.t1 - E)) m[sec.line(s)] = s;
  });
  return m;
}
function buildPicker(){
  var host = document.getElementById("pklist"); host.innerHTML = "";
  document.getElementById("scount").textContent = PTS.length + " snapshots";
  PTS.forEach(function(t, i){
    var r = document.createElement("div"); r.className = "pk"; r.dataset.i = i;
    var a = document.createElement("span"); a.className = "i"; a.textContent = "#"+(i+1);
    var b = document.createElement("span");
    b.textContent = new Date(t*1000).toLocaleTimeString(undefined,
      {hour:"2-digit",minute:"2-digit",second:"2-digit"});
    r.appendChild(a); r.appendChild(b);
    r.addEventListener("click", function(e){
      if(e.shiftKey && lastClick !== null){
        var lo = Math.min(lastClick, i), hi = Math.max(lastClick, i);
        picked = []; for(var j=lo; j<=hi; j++) picked.push(j);
      } else {
        var at = picked.indexOf(i);
        if(at >= 0) picked.splice(at,1); else picked.push(i);
        lastClick = i;
      }
      picked.sort(function(x,y){return x-y});
      drawSnaps();
    });
    host.appendChild(r);
  });
}
document.getElementById("pkclear").addEventListener("click", function(){
  picked = []; lastClick = null; drawSnaps();
});
function dline(cls, text){
  var d = document.createElement("div"); d.className = cls;
  if(typeof text === "string") d.textContent = text; else d.appendChild(text);
  return d;
}
function drawSnaps(){
  if(!document.getElementById("pklist").children.length) buildPicker();
  document.querySelectorAll(".pk").forEach(function(r){
    r.classList.toggle("on", picked.indexOf(+r.dataset.i) >= 0);
  });
  document.getElementById("pksel").textContent = picked.length + " selected";
  var out = document.getElementById("snapout"); out.innerHTML = "";

  if(!picked.length){
    out.appendChild(dline("empty",
      "Select a snapshot on the left to see the host's exact state at that moment. "+
      "Select two or more to compare them."));
    return;
  }

  /* ---- single snapshot: full state ---- */
  if(picked.length === 1){
    var t = PTS[picked[0]];
    var sum = el("div","sumline");
    sum.innerHTML = "";
    sum.appendChild(document.createTextNode("Reconstructed state at snapshot #"+
      (picked[0]+1)+" — "+ts(t)));
    out.appendChild(sum);
    SEC.forEach(function(sec){
      var m = stateAt(sec, t), keys = Object.keys(m).sort();
      var g = el("div","dgroup"), h = el("div","dhead");
      h.appendChild(el("span",null,sec.k));
      var c = el("span"); c.innerHTML = "<b>"+keys.length+"</b> present"; h.appendChild(c);
      g.appendChild(h);
      var box = el("div","dl");
      if(!keys.length) box.appendChild(dline("none","  (none)"));
      keys.forEach(function(k){ box.appendChild(dline("same","  "+k)); });
      g.appendChild(box); out.appendChild(g);
    });
    return;
  }

  /* ---- 2+ snapshots: compare ---- */
  var times = picked.map(function(i){return PTS[i]});
  var hdr = el("div","sumline");
  hdr.appendChild(document.createTextNode("Comparing "+picked.length+" snapshots:  "));
  picked.forEach(function(i,n){
    hdr.appendChild(document.createTextNode(
      (n?"    ":"")+"S"+(n+1)+" = #"+(i+1)+" "+ts(PTS[i])));
  });
  out.appendChild(hdr);

  var totalDiff = 0;
  SEC.forEach(function(sec){
    var maps = times.map(function(t){ return stateAt(sec, t); });
    var union = {}, keys;
    maps.forEach(function(m){ for(var k in m) union[k]=1; });
    keys = Object.keys(union).sort();
    var diffs = keys.filter(function(k){
      return maps.some(function(m){ return !(k in m); });
    });
    var same = keys.length - diffs.length;
    totalDiff += diffs.length;

    var g = el("div","dgroup"), h = el("div","dhead");
    h.appendChild(el("span",null,sec.k));
    var c = el("span");
    c.innerHTML = same+" identical &middot; <b>"+diffs.length+"</b> differing";
    h.appendChild(c); g.appendChild(h);

    var box = el("div","dl");
    if(!diffs.length){
      box.appendChild(dline("none","  (no change)"));
    } else if(picked.length === 2){
      diffs.forEach(function(k){
        var inB = k in maps[1];
        box.appendChild(dline(inB?"add":"rem", (inB?"  + ":"  - ")+k));
        var ev = maps[1][k] || maps[0][k];
        if(sec.extra){ var x = sec.extra(ev); if(x) box.appendChild(dline("exe",x)); }
      });
    } else {
      var head = "  " + picked.map(function(_,n){return "S"+(n+1)}).join(" ") + "   entity";
      box.appendChild(dline("mat", head));
      diffs.forEach(function(k){
        var mark = maps.map(function(m){ return (k in m) ? " X" : " ."; }).join(" ");
        box.appendChild(dline("mat", "  "+mark+"   "+k));
      });
    }
    g.appendChild(box); out.appendChild(g);
  });

  var foot = el("div","sumline");
  foot.innerHTML = "<b>"+totalDiff+"</b> differing line(s) across "+SEC.length+" sections.";
  out.appendChild(foot);
}

/* ---------- timeline ---------- */
function drawTL(){
  var q=document.getElementById("tlf").value.toLowerCase();
  var showBase=document.getElementById("tlb").value==="1";
  var rows=D.spans.filter(function(s){
    if(!showBase&&s.base) return false;
    if(q&&(s.cmd+" "+(s.comm||"")).toLowerCase().indexOf(q)<0) return false;
    return true;
  }).slice(0,150);
  document.getElementById("tlcount").textContent=rows.length+" of "+D.spans.length+" spans";
  var host=document.getElementById("tl"); host.innerHTML="";
  var W=Math.max(760, host.clientWidth-2), LEFT=210, RH=17, PAD=30;
  var H=PAD+rows.length*RH+34;
  var span=Math.max(1,T1-T0);
  function X(t){ return LEFT+((t-T0)/span)*(W-LEFT-18); }
  var NS="http://www.w3.org/2000/svg";
  function mk(t,a){ var e=document.createElementNS(NS,t);
    for(var k in a) e.setAttribute(k,a[k]); return e; }
  var svg=mk("svg",{width:W,height:H});
  var C={ink:css("--ink"),ink3:css("--ink-3"),line:css("--line"),
         hi:css("--hi"),net:css("--net"),warn:css("--warn"),ink2:css("--ink-2")};
  // time gridlines
  for(var g=0; g<=6; g++){
    var t=T0+span*g/6, x=X(t);
    svg.appendChild(mk("line",{x1:x,y1:PAD-8,x2:x,y2:H-26,stroke:C.line,"stroke-width":1}));
    var lb=mk("text",{x:x,y:H-12,fill:C.ink3,"font-size":9.5,"text-anchor":"middle",
      "font-family":css("--m")});
    lb.textContent=new Date(t*1000).toLocaleTimeString(undefined,{hour:"2-digit",minute:"2-digit",second:"2-digit"});
    svg.appendChild(lb);
  }
  rows.forEach(function(s,i){
    var y=PAD+i*RH;
    var lbl=mk("text",{x:6,y:y+9,fill:C.ink2,"font-size":10,
      "font-family":css("--m")});
    lbl.textContent=(s.comm||"?").slice(0,24)+" "+s.pid;
    svg.appendChild(lbl);
    var x1=X(s.t0), x2=Math.max(X(s.t1),x1+2);
    var bar=mk("rect",{x:x1,y:y+1,width:x2-x1,height:RH-6,rx:1.5,
      fill:s.open?C.net:C.ink2, opacity:s.open?0.75:0.55});
    bar.appendChild(mk("title")).textContent=s.cmd+"\n"+
      (s.life!==null&&s.life!==undefined?("lifetime "+s.life+"s"):"still running");
    svg.appendChild(bar);
  });
  // connection dots along the bottom
  var cy=H-30;
  D.conns.forEach(function(c){
    if(q&&(c.comm+" "+c.ip).toLowerCase().indexOf(q)<0) return;
    var d=mk("circle",{cx:X(c.t),cy:cy,r:2.6,fill:c.ext?C.hi:C.ink3,opacity:0.85});
    d.appendChild(mk("title")).textContent=c.comm+" → "+c.ip+":"+c.port;
    svg.appendChild(d);
  });
  var cl=mk("text",{x:6,y:cy+4,fill:C.ink3,"font-size":9,
    "font-family":css("--m")});
  cl.textContent="connections";
  svg.appendChild(cl);
  host.appendChild(svg);
}
document.getElementById("tlf").addEventListener("input",drawTL);
document.getElementById("tlb").addEventListener("change",drawTL);
sizeCanvas();
/* deep links: #graph, #timeline, #procs, #net, #snaps, or #snaps=1,12,last to open a comparison */
(function(){
  var h=(location.hash||"").slice(1); if(!h) return;
  var m=h.match(/^snaps=([0-9,last]+)$/);
  var tab=m?"snaps":h, btn=document.querySelector('.tab[data-p="'+tab+'"]');
  if(!btn) return;
  if(m){ picked=[]; m[1].split(",").forEach(function(x){
      var i = x==="last" ? PTS.length-1 : parseInt(x,10)-1;
      if(i>=0 && i<PTS.length && picked.indexOf(i)<0) picked.push(i); });
    picked.sort(function(a,b){return a-b}); }
  btn.click();
})();
</script>
</body></html>
"""


# ==========================================================================
# triage report
# ==========================================================================
def render_triage(res, base=None) -> str:
    data = {"r": res, "diff": ps.triage_diff(base, res) if base else None,
            "base": {"host": base["host"].get("hostname"), "started": base["started"]}
            if base else None}
    title = f"Triage · {res['host'].get('hostname', '?')}"
    return fill(TRIAGE_TEMPLATE, data, TITLE=title, VERSION=res.get("version", ps.VERSION))


TRIAGE_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>__TITLE__</title>
<style>
:root{
  --brand:#c8102e;
  --paper:#f4f5f7; --surface:#ffffff; --surface-2:#f0f2f5; --surface-3:#e5e9ee;
  --ink:#10151b; --ink-2:#4a5561; --ink-3:#7b8794; --line:#dde2e8; --line-2:#c9d0d8;
  --crit:#d03b3b; --high:#ec835a; --med:#fab219; --low:#3987e5; --info:#8b96a3; --ok:#0ca30c;
  --crit-soft:#fbe9e9; --high-soft:#fdf0ea; --med-soft:#fef6e3; --low-soft:#eaf2fc; --info-soft:#eff1f4;
  --f:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --m:ui-monospace,"SFMono-Regular","Cascadia Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --paper:#0b0e12; --surface:#12171d; --surface-2:#182029; --surface-3:#202a35;
  --ink:#e8edf2; --ink-2:#a3afbb; --ink-3:#6f7d8b; --line:#232d38; --line-2:#2f3b48;
  --crit-soft:#3a1617; --high-soft:#3a2117; --med-soft:#33280f; --low-soft:#142439; --info-soft:#1b222b;
}}
:root[data-theme="dark"]{
  --paper:#0b0e12; --surface:#12171d; --surface-2:#182029; --surface-3:#202a35;
  --ink:#e8edf2; --ink-2:#a3afbb; --ink-3:#6f7d8b; --line:#232d38; --line-2:#2f3b48;
  --crit-soft:#3a1617; --high-soft:#3a2117; --med-soft:#33280f; --low-soft:#142439; --info-soft:#1b222b;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.55 var(--f);
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1360px;margin:0 auto;padding:0 20px}
h1,h2,h3{margin:0;letter-spacing:-.015em;text-wrap:balance}
button{font:inherit;color:inherit}
a{color:inherit}
.mono{font-family:var(--m)}
.k-label{font-family:var(--m);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-3)}

/* ---------- hero ---------- */
.hero{background:var(--surface);border-bottom:1px solid var(--line);position:relative}
.hero::before{content:"";position:absolute;inset:0 0 auto 0;height:3px;background:var(--brand)}
.hero-in{padding:26px 0 22px;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:18px 32px;align-items:start}
@media(max-width:860px){.hero-in{grid-template-columns:1fr}}
.brand{display:flex;align-items:center;gap:10px;font-family:var(--m);font-size:11px;
  letter-spacing:.16em;text-transform:uppercase;color:var(--ink-3)}
.brand b{color:var(--brand);font-weight:700}
.brand .sep{width:1px;height:12px;background:var(--line-2)}
h1{font-size:clamp(24px,3.4vw,36px);font-weight:750;margin:10px 0 4px;overflow-wrap:anywhere}
.sub{color:var(--ink-2);font-size:13px;display:flex;flex-wrap:wrap;gap:4px 14px}
.sub span{white-space:nowrap}
.tools{display:flex;gap:8px;align-items:center;justify-content:flex-end}
.btn{background:var(--surface-2);border:1px solid var(--line);border-radius:6px;padding:6px 11px;
  font-size:12px;cursor:pointer;color:var(--ink-2)}
.btn:hover{color:var(--ink);border-color:var(--line-2)}
.btn:focus-visible,.tab:focus-visible,.chip:focus-visible{outline:2px solid var(--brand);outline-offset:2px}

.verdict{grid-column:1/-1;display:flex;flex-wrap:wrap;gap:14px 26px;align-items:center;
  border:1px solid var(--line);border-radius:10px;padding:16px 18px;background:var(--surface-2)}
.verdict .v-badge{display:flex;align-items:center;gap:12px}
.v-dot{width:14px;height:14px;border-radius:50%;flex:none;box-shadow:0 0 0 4px var(--surface)}
.v-text{font-size:19px;font-weight:700}
.v-desc{color:var(--ink-2);font-size:13px;max-width:62ch}
.verdict.compromised{background:var(--crit-soft);border-color:color-mix(in srgb,var(--crit) 40%,var(--line))}
.verdict.suspicious{background:var(--high-soft);border-color:color-mix(in srgb,var(--high) 40%,var(--line))}
.verdict.review{background:var(--med-soft);border-color:color-mix(in srgb,var(--med) 40%,var(--line))}
.verdict.clean{background:var(--surface-2)}

.tiles{grid-column:1/-1;display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:10px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:11px 14px;
  text-align:left;cursor:default;position:relative;overflow:hidden}
button.tile{cursor:pointer}
button.tile:hover{border-color:var(--line-2)}
.tile .v{font-size:26px;font-weight:750;font-variant-numeric:tabular-nums;line-height:1.15;margin-top:3px}
.tile .bar{position:absolute;left:0;top:0;bottom:0;width:4px}
.tile.zero .v{color:var(--ink-3)}

.sevbar{grid-column:1/-1}
.sb-track{display:flex;gap:2px;height:10px;border-radius:5px;overflow:hidden;background:var(--surface-3)}
.sb-track span{display:block;height:100%}
.sb-leg{display:flex;flex-wrap:wrap;gap:4px 16px;margin-top:8px;font-size:12px;color:var(--ink-2)}
.sb-leg i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:6px;vertical-align:-1px}

/* ---------- tabs ---------- */
.tabs{position:sticky;top:0;z-index:30;background:color-mix(in srgb,var(--surface) 92%,transparent);
  backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.tabs .wrap{display:flex;gap:2px;overflow-x:auto;scrollbar-width:none}
.tab{background:none;border:0;border-bottom:2px solid transparent;padding:13px 13px 11px;cursor:pointer;
  color:var(--ink-3);font-size:13px;font-weight:600;white-space:nowrap}
.tab:hover{color:var(--ink)}
.tab.on{color:var(--ink);border-bottom-color:var(--brand)}
.tab .n{font-family:var(--m);font-size:10.5px;font-weight:500;margin-left:6px;color:var(--ink-3);
  background:var(--surface-2);border:1px solid var(--line);border-radius:9px;padding:0 6px}
.pane{display:none;padding:24px 0 64px}
.pane.on{display:block}

/* ---------- cards / sections ---------- */
.grid2{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);gap:18px}
@media(max-width:980px){.grid2{grid-template-columns:1fr}}
.card{background:var(--surface);border:1px solid var(--line);border-radius:10px;margin-bottom:18px}
.card-h{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap;
  padding:13px 16px;border-bottom:1px solid var(--line)}
.card-h h2{font-size:15px;font-weight:700}
.card-b{padding:14px 16px}
.muted{color:var(--ink-3)}
.note{font-size:12.5px;color:var(--ink-2);background:var(--surface-2);border-left:3px solid var(--line-2);
  padding:8px 12px;border-radius:0 6px 6px 0;margin:0 0 12px}
.empty{color:var(--ink-3);font-size:13px;padding:6px 0}

/* severity badge: colour + glyph + word, never colour alone */
.sev{display:inline-flex;align-items:center;gap:6px;font-family:var(--m);font-size:10.5px;font-weight:700;
  letter-spacing:.08em;text-transform:uppercase;padding:2px 8px 2px 7px;border-radius:5px;white-space:nowrap;
  color:var(--ink);background:var(--info-soft);border:1px solid var(--line)}
.sev i{font-style:normal;font-size:10px}
.sev.critical{background:var(--crit-soft)} .sev.critical i{color:var(--crit)}
.sev.high{background:var(--high-soft)} .sev.high i{color:var(--high)}
.sev.medium{background:var(--med-soft)} .sev.medium i{color:var(--med)}
.sev.low{background:var(--low-soft)} .sev.low i{color:var(--low)}
.sev.info i{color:var(--info)}
.chipm{font-family:var(--m);font-size:10.5px;padding:1px 7px;border-radius:5px;border:1px solid var(--line);
  background:var(--surface-2);color:var(--ink-2);text-decoration:none;white-space:nowrap}
a.chipm:hover{color:var(--ink);border-color:var(--line-2)}
.tag{font-size:11px;color:var(--ink-3);white-space:nowrap}

/* top findings */
.tf{display:grid;grid-template-columns:auto minmax(0,1fr);gap:4px 12px;padding:10px 0;
  border-bottom:1px dashed var(--line);cursor:pointer}
.tf:last-child{border-bottom:0}
.tf:hover .tf-t{text-decoration:underline;text-underline-offset:3px}
.tf-t{font-weight:600;overflow-wrap:anywhere}
.tf-m{grid-column:2;font-size:12px;color:var(--ink-3);display:flex;flex-wrap:wrap;gap:6px}

/* ATT&CK */
.attack{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px}
.tac{border:1px solid var(--line);border-radius:8px;background:var(--surface-2);padding:9px 10px;min-height:76px}
.tac h3{font-size:11.5px;font-weight:700;color:var(--ink-2);margin-bottom:7px}
.tac.hit{background:var(--surface)}
.tech{display:flex;gap:7px;align-items:flex-start;width:100%;text-align:left;background:none;border:0;
  padding:4px 0;cursor:pointer;font-size:12px;line-height:1.35;color:var(--ink)}
.tech:hover span:last-child{text-decoration:underline}
.tech .d{width:8px;height:8px;border-radius:50%;margin-top:4px;flex:none}
.tech b{font-family:var(--m);font-size:10.5px;font-weight:600;color:var(--ink-2);display:block}
.tac .none{font-size:12px;color:var(--ink-3)}

dl.facts{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:7px 18px;margin:0;font-size:13px}
dl.facts dt{color:var(--ink-3)}
dl.facts dd{margin:0;overflow-wrap:anywhere}

/* findings */
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:16px}
.chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);background:var(--surface);
  border-radius:16px;padding:5px 11px;font-size:12.5px;cursor:pointer;color:var(--ink-2)}
.chip[aria-pressed="true"]{border-color:var(--ink-2);color:var(--ink);background:var(--surface-2)}
.chip .d{width:8px;height:8px;border-radius:50%}
.chip .c{font-family:var(--m);font-size:11px;color:var(--ink-3)}
.inp{font:13px var(--f);padding:6px 10px;border:1px solid var(--line-2);border-radius:7px;
  background:var(--surface);color:var(--ink);min-width:0}
.inp:focus-visible{outline:2px solid var(--brand);outline-offset:1px}
.grow{flex:1 1 220px}
details.fd{background:var(--surface);border:1px solid var(--line);border-radius:10px;margin-bottom:10px;
  border-left-width:4px}
details.fd.critical{border-left-color:var(--crit)} details.fd.high{border-left-color:var(--high)}
details.fd.medium{border-left-color:var(--med)} details.fd.low{border-left-color:var(--low)}
details.fd.info{border-left-color:var(--info)}
details.fd.flash{animation:flash 1.4s ease}
@keyframes flash{0%{box-shadow:0 0 0 3px var(--brand)}100%{box-shadow:0 0 0 0 transparent}}
details.fd>summary{list-style:none;cursor:pointer;padding:12px 15px;display:grid;
  grid-template-columns:auto minmax(0,1fr) auto;gap:4px 12px;align-items:start}
details.fd>summary::-webkit-details-marker{display:none}
.fd-t{font-weight:600;overflow-wrap:anywhere}
.fd-m{grid-column:2;display:flex;flex-wrap:wrap;gap:6px;align-items:center;font-size:12px;color:var(--ink-3)}
.fd-x{color:var(--ink-3);font-size:12px;transition:transform .15s}
details[open]>summary .fd-x{transform:rotate(90deg)}
.fd-b{padding:0 15px 15px 15px;border-top:1px solid var(--line)}
.fd-b p{margin:12px 0 0;max-width:90ch;color:var(--ink-2)}
.fd-b p.fix{color:var(--ink);background:var(--surface-2);border-radius:6px;padding:8px 11px}
.fd-b p.fix::before{content:"Next step  ";font-family:var(--m);font-size:10px;letter-spacing:.12em;
  text-transform:uppercase;color:var(--ink-3)}
table.kv{border-collapse:collapse;width:100%;margin-top:12px;font-size:12.5px}
table.kv th{text-align:left;font-weight:500;color:var(--ink-3);padding:5px 14px 5px 0;vertical-align:top;
  white-space:nowrap;width:1%;font-family:var(--m);font-size:11px}
table.kv td{padding:5px 0;font-family:var(--m);overflow-wrap:anywhere;word-break:break-word}
table.kv td div{padding:1px 0}
.copy{margin-left:8px;font-size:10.5px;padding:1px 7px;border-radius:5px;border:1px solid var(--line);
  background:var(--surface-2);cursor:pointer;color:var(--ink-3);font-family:var(--f)}
.copy:hover{color:var(--ink)}

/* tables */
.tw{overflow:auto;max-height:640px;border-top:1px solid var(--line)}
table.t{border-collapse:separate;border-spacing:0;width:100%;font-size:12.5px}
table.t th{position:sticky;top:0;z-index:1;background:var(--surface-2);text-align:left;font-weight:600;
  font-size:11px;color:var(--ink-2);padding:8px 12px;border-bottom:1px solid var(--line);white-space:nowrap;
  cursor:pointer;user-select:none}
table.t th:hover{color:var(--ink)}
table.t th[aria-sort]::after{content:" ↑";color:var(--ink-3)}
table.t th[aria-sort="descending"]::after{content:" ↓"}
table.t td{padding:7px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-family:var(--m);
  font-size:12px;color:var(--ink-2);max-width:560px;overflow-wrap:break-word}
table.t tr:last-child td{border-bottom:0}
table.t tr.hot td{background:var(--crit-soft);color:var(--ink)}
table.t tr.warm td{background:color-mix(in srgb,var(--med-soft) 60%,transparent)}
table.t td.num{text-align:right;font-variant-numeric:tabular-nums}
.clamp{display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
@media print{.clamp{-webkit-line-clamp:unset;display:block}}
.pill{display:inline-block;font-family:var(--m);font-size:10px;padding:1px 6px;margin:0 3px 2px 0;border-radius:4px;
  background:var(--surface-3);color:var(--ink-2);white-space:nowrap}
.pill.hot{background:var(--crit-soft);color:var(--ink);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--crit) 45%,transparent)}
.more{display:block;width:100%;padding:9px;border:0;border-top:1px solid var(--line);background:var(--surface-2);
  cursor:pointer;color:var(--ink-2);font-size:12.5px;border-radius:0 0 10px 10px}
.sec-tools{display:flex;gap:8px;align-items:center}
.cnt{font-family:var(--m);font-size:11.5px;color:var(--ink-3)}

/* process tree */
.ptree{font-family:var(--m);font-size:12px;max-height:720px;overflow:auto;border-top:1px solid var(--line)}
.pr{display:grid;grid-template-columns:minmax(0,1fr);padding:3px 14px;border-bottom:1px dotted var(--line)}
.pr:hover{background:var(--surface-2)}
.pr .line{white-space:pre;overflow:hidden;text-overflow:ellipsis}
.pr .pid{color:var(--ink-3)}
.pr .usr{color:var(--ink-3)}
.pr .cm{color:var(--ink)}
.pr.hot{background:var(--crit-soft)}
.pr.me{opacity:.55}
.guide{color:var(--line-2)}

/* run info */
.tbar{display:grid;grid-template-columns:150px minmax(0,1fr) 64px;gap:10px;align-items:center;font-size:12.5px;padding:3px 0}
.tbar .track{height:8px;background:var(--surface-3);border-radius:4px;overflow:hidden}
.tbar .track span{display:block;height:100%;background:var(--ink-3);border-radius:4px}
.tbar .s{font-family:var(--m);text-align:right;color:var(--ink-2)}
ul.lim{margin:0;padding-left:18px;color:var(--ink-2)}
ul.lim li{margin:5px 0}

.diffrow-add td{background:color-mix(in srgb,var(--ok) 10%,transparent)}
.diffrow-rem td{background:var(--crit-soft);text-decoration:line-through;text-decoration-color:var(--ink-3)}

footer{border-top:1px solid var(--line);padding:18px 0 40px;font-size:12px;color:var(--ink-3)}
footer .wrap{display:flex;flex-wrap:wrap;gap:8px 20px;justify-content:space-between}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media print{
  .tabs,.tools,.filters,.more,.sec-tools input{display:none!important}
  .pane{display:block!important;padding-top:8px}
  .tw,.ptree{max-height:none;overflow:visible}
  details.fd{break-inside:avoid}
  body{background:#fff}
}
</style></head><body>

<header class="hero"><div class="wrap hero-in">
  <div>
    <div class="brand"><b>RedSide Security</b><span class="sep"></span><span>ProcSnap live triage</span></div>
    <h1 id="host"></h1>
    <div class="sub" id="sub"></div>
  </div>
  <div class="tools">
    <button class="btn" id="theme" type="button">Theme</button>
    <button class="btn" id="print" type="button">Print / PDF</button>
  </div>
  <div class="verdict" id="verdict"></div>
  <div class="tiles" id="tiles"></div>
  <div class="sevbar" id="sevbar"></div>
</div></header>

<nav class="tabs" aria-label="Report sections"><div class="wrap" id="tabs"></div></nav>

<main class="wrap">
  <section class="pane" id="p-overview"></section>
  <section class="pane" id="p-findings"></section>
  <section class="pane" id="p-processes"></section>
  <section class="pane" id="p-network"></section>
  <section class="pane" id="p-persistence"></section>
  <section class="pane" id="p-accounts"></section>
  <section class="pane" id="p-system"></section>
  <section class="pane" id="p-intel"></section>
  <section class="pane" id="p-evidence"></section>
  <section class="pane" id="p-changes"></section>
  <section class="pane" id="p-run"></section>
</main>

<footer><div class="wrap">
  <span id="foot"></span>
  <span>ProcSnap __VERSION__ · RedSide Security · self-contained report, works offline</span>
</div></footer>

<script id="data" type="application/json">__DATA__</script>
<script>
"use strict";
var D = JSON.parse(document.getElementById("data").textContent);
var R = D.r, DIFF = D.diff;
var SEV = ["critical","high","medium","low","info"];
var GLYPH = {critical:"⬢", high:"▲", medium:"◆", low:"●", info:"○"};
var VAR = {critical:"--crit", high:"--high", medium:"--med", low:"--low", info:"--info"};
var CAT = {process:"Process", network:"Network", kernel:"Kernel", persistence:"Persistence",
           accounts:"Accounts", logs:"Logs & history", integrity:"Integrity", filesystem:"Filesystem",
           intel:"Threat intel"};
var WEAK = {"external":1,"recent":1,"analyst-session":1,"notty":1,"unpackaged":1,"dkms":1,"keys2":0,"ww-ref":1,
            "hosting":1,"proxy/vpn":1,"unknown":1};

function el(t, c, x){ var e=document.createElement(t); if(c) e.className=c;
  if(x!==undefined && x!==null) e.textContent=String(x); return e; }
function add(p){ for(var i=1;i<arguments.length;i++){ var c=arguments[i];
  if(c===null||c===undefined) continue; p.appendChild(typeof c==="string"?document.createTextNode(c):c);} return p; }
function cssv(v){ return "var("+v+")"; }
function fmt(t){ if(!t) return "?"; var d=new Date(t*1000);
  return d.toISOString().replace("T"," ").slice(0,19)+" UTC"; }
function dur(s){ s=Math.round(s||0); var d=Math.floor(s/86400), h=Math.floor(s%86400/3600), m=Math.floor(s%3600/60);
  return d? d+"d "+h+"h" : h? h+"h "+m+"m" : m+"m"; }
function sevBadge(s){ var b=el("span","sev "+s); add(b, el("i",null,GLYPH[s]), s); return b; }
function mitreChip(id){ var a=el("a","chipm",id); a.href="https://attack.mitre.org/techniques/"+id.replace(".","/")+"/";
  a.target="_blank"; a.rel="noopener noreferrer"; var m=R.mitre[id]; if(m) a.title=m.name+" — "+m.tactic; return a; }
function copyBtn(text){ var b=el("button","copy","copy"); b.type="button";
  b.addEventListener("click",function(e){ e.preventDefault(); e.stopPropagation();
    (navigator.clipboard?navigator.clipboard.writeText(text):Promise.reject()).then(function(){
      b.textContent="copied"; setTimeout(function(){b.textContent="copy"},1200); },function(){
      var ta=el("textarea"); ta.value=text; document.body.appendChild(ta); ta.select();
      try{document.execCommand("copy"); b.textContent="copied";}catch(_){} ta.remove(); }); });
  return b; }

/* ================= hero ================= */
var H = R.host;
document.getElementById("host").textContent = H.hostname || "?";
(function(){
  var s=document.getElementById("sub");
  [H.os, H.kernel?("kernel "+H.kernel):null, H.arch, H.mode, H.uptime_s?("up "+dur(H.uptime_s)):null,
   "triaged "+fmt(R.started)].forEach(function(x){ if(x) add(s, el("span",null,x)); });
})();
(function(){
  var v=R.verdict, box=document.getElementById("verdict");
  box.classList.add(v.level);
  var col={compromised:"--crit",suspicious:"--high",review:"--med",clean:"--ok"}[v.level];
  var dot=el("span","v-dot"); dot.style.background=cssv(col);
  var desc={compromised:"At least one critical indicator was found. Treat the host as compromised: isolate it, preserve memory and disk, and work through the critical findings first.",
    suspicious:"High-severity findings need an analyst's judgement. Confirm or rule out each one before closing.",
    review:"No strong indicators. Medium findings are context that may still matter for this host's role.",
    clean:"No indicators found. A poller-free snapshot cannot see kernel rootkits that lie to /proc; see Run info for the limits."}[v.level];
  add(box, add(el("div","v-badge"), dot, add(el("div"), el("div","k-label","Verdict"), el("div","v-text",v.text))),
      el("div","v-desc",desc));
})();
(function(){
  var t=document.getElementById("tiles");
  ["critical","high","medium","low"].forEach(function(s){
    var n=R.counts[s]||0, b=el("button","tile"+(n?"":" zero")); b.type="button";
    var bar=el("span","bar"); bar.style.background=n?cssv(VAR[s]):"var(--line)";
    add(b, bar, add(el("div","k-label"), GLYPH[s]+" "+s), el("div","v",n));
    b.title="Show "+s+" findings";
    b.addEventListener("click",function(){ FS.sev={}; FS.sev[s]=1; FS.mitre=""; drawFindings(); show("findings"); });
    t.appendChild(b);
  });
  [["evidence files",R.evidence.filter(function(e){return e.saved}).length+" / "+R.evidence.length],
   ["checks run",Object.keys(R.timings).length],["duration",(R.duration_s<1?"<1":Math.round(R.duration_s))+"s"]].forEach(function(p){
    var d=el("div","tile"); add(d, el("div","k-label",p[0]), el("div","v",p[1])); t.appendChild(d); });
})();
(function(){
  var box=document.getElementById("sevbar"), tot=0;
  SEV.slice(0,4).forEach(function(s){ tot+=R.counts[s]||0; });
  var tr=el("div","sb-track"); tr.setAttribute("role","img");
  var lab=[];
  SEV.slice(0,4).forEach(function(s){ var n=R.counts[s]||0; lab.push(n+" "+s);
    if(!n) return; var sp=el("span"); sp.style.flex=String(n); sp.style.background=cssv(VAR[s]);
    sp.title=n+" "+s; tr.appendChild(sp); });
  tr.setAttribute("aria-label","Findings by severity: "+lab.join(", "));
  var leg=el("div","sb-leg");
  SEV.slice(0,4).forEach(function(s){ var i=el("i"); i.style.background=cssv(VAR[s]);
    add(leg, add(el("span"), i, s+" "+(R.counts[s]||0))); });
  if(!tot) add(leg, el("span",null,"— no findings above info"));
  add(box, tr, leg);
})();

/* ================= tabs ================= */
var invByTab = {network:[], persistence:[], accounts:[], system:[], intel:[]};
var TABMAP = {network:"network", persistence:"persistence", accounts:"accounts", logs:"accounts",
              kernel:"system", integrity:"system", filesystem:"system", intel:"intel"};
Object.keys(R.inventory).forEach(function(k){
  var inv=R.inventory[k]; if(k==="processes") return;
  var tab=TABMAP[inv.cat]||"system"; invByTab[tab].push(k);
});
var TABS=[["overview","Overview"],["findings","Findings",R.findings.length],
  ["processes","Processes",(R.inventory.processes||{rows:[]}).rows.length],
  ["network","Network"],["persistence","Persistence"],["accounts","Accounts & logins"],
  ["system","System & files"],["intel","Threat intel",R.findings.filter(function(f){return f.cat==="intel"}).length],
  ["evidence","Evidence",R.evidence.length],
  ["changes","Changes",DIFF?(DIFF.findings["new"].length+DIFF.findings.gone.length):null],["run","Run info"]];
var drawn={};
(function(){
  var nav=document.getElementById("tabs");
  TABS.forEach(function(t){
    if(t[0]==="processes" && !R.inventory.processes) return;
    if(t[0]==="network" && !invByTab.network.length) return;
    if(t[0]==="intel" && !R.intel) return;
    var b=el("button","tab",t[1]); b.type="button"; b.dataset.p=t[0];
    if(t[2]!==undefined && t[2]!==null) add(b, el("span","n",t[2]));
    b.addEventListener("click",function(){ show(t[0]); });
    nav.appendChild(b);
  });
})();
function show(p){
  document.querySelectorAll(".tab").forEach(function(b){ b.classList.toggle("on", b.dataset.p===p);
    b.setAttribute("aria-selected", b.dataset.p===p?"true":"false"); });
  document.querySelectorAll(".pane").forEach(function(s){ s.classList.toggle("on", s.id==="p-"+p); });
  if(!drawn[p]){ drawn[p]=1; (DRAW[p]||function(){})(); }
  if(history.replaceState) history.replaceState(null,"","#"+p);
}

/* ================= overview ================= */
function maxSev(fs){ var best=4; fs.forEach(function(f){ best=Math.min(best,SEV.indexOf(f.sev)); }); return SEV[best]; }
function drawOverview(){
  var p=document.getElementById("p-overview"), g=el("div","grid2");
  var left=el("div"), right=el("div");
  /* top findings */
  var c=el("div","card"), h=el("div","card-h");
  add(h, el("h2",null,"Top findings"), el("span","cnt","critical and high, most severe first"));
  var b=el("div","card-b"), top=R.findings.filter(function(f){return f.sev==="critical"||f.sev==="high"}).slice(0,10);
  if(!top.length) add(b, el("div","empty","No critical or high findings."));
  top.forEach(function(f){
    var r=el("div","tf"); r.tabIndex=0; r.setAttribute("role","button");
    var m=el("div","tf-m"); add(m, el("span","tag",CAT[f.cat]||f.cat));
    f.mitre.forEach(function(id){ add(m, el("span","chipm",id)); });
    add(r, sevBadge(f.sev), el("div","tf-t",f.title), m);
    function go(){ openFinding(f.id); }
    r.addEventListener("click",go); r.addEventListener("keydown",function(e){ if(e.key==="Enter") go(); });
    b.appendChild(r);
  });
  add(left, add(c, h, b));

  /* who is on the box right now */
  var S=R.inventory.sessions;
  if(S){
    var sc=el("div","card"), sh=el("div","card-h");
    add(sh, el("h2",null,"Logged in now"), el("span","cnt",S.rows.length+" session"+(S.rows.length===1?"":"s")));
    var sb=el("div","card-b"), ci=function(n){return S.cols.indexOf(n)};
    if(!S.rows.length) add(sb, el("div","empty","Nobody is logged in."));
    S.rows.forEach(function(r){
      var fl=r[ci("flags")]||[], row=el("div","tf"); row.style.cursor="default";
      var who=el("div","tf-t"); add(who, r[ci("user")]+"@"+r[ci("tty")]+"  from "+r[ci("from")]);
      var m=el("div","tf-m");
      add(m, el("span","tag","since "+r[ci("login")]), el("span","chipm",r[ci("session length")]),
          r[ci("idle")]?el("span","tag","idle "+r[ci("idle")]):null,
          el("span","tag","via "+r[ci("seen in")]), r[ci("running")]?el("span","tag mono",r[ci("running")]):null);
      fl.forEach(function(x){ add(m, el("span","pill"+(WEAK[x]?"":" hot"),x)); });
      add(row, el("span","sev "+(isHot(fl)?"high":"info"), isHot(fl)?"\u25B2 check":"\u25CB user"), who, m);
      sb.appendChild(row);
    });
    add(left, add(sc, sh, sb));
  }

  /* host facts */
  var fc=el("div","card"); add(fc, add(el("div","card-h"), el("h2",null,"Host")));
  var dl=el("dl","facts");
  var F=[["Hostname",H.hostname],["OS",H.os],["Kernel",H.kernel],["Architecture",H.arch],["Mode",H.mode],
    ["Booted",H.boot?fmt(H.boot):null],["Uptime",H.uptime_s?dur(H.uptime_s):null],["Timezone",H.timezone],
    ["Addresses",(H.addresses||[]).join(", ")],["Kernel taint",H.tainted?(H.tainted+(H.tainted_flags?" — "+H.tainted_flags:"")):"0 (clean)"],
    ["Packages (dpkg)",H.dpkg_packages],["Files checksum-verified",H.dpkg_files_verified!==undefined?(H.dpkg_files_verified+" ("+H.dpkg_scope+")"):null],
    ["Files swept",H.files_swept],["PID range brute-forced",H.pid_scan],["Login records (wtmp)",H.wtmp_records],
    ["Ran as root",H.root_privileges?"yes":"NO — results are partial"]];
  F.forEach(function(x){ if(x[1]===undefined||x[1]===null||x[1]==="") return;
    add(dl, el("dt",null,x[0]), el("dd",null,x[1])); });
  add(fc, add(el("div","card-b"), dl)); add(left, fc);

  /* ATT&CK */
  var ac=el("div","card"), ah=el("div","card-h");
  add(ah, el("h2",null,"MITRE ATT&CK coverage"), el("span","cnt",Object.keys(R.mitre).length+" techniques"));
  var grid=el("div","attack");
  R.tactics.forEach(function(tac){
    var ids=Object.keys(R.mitre).filter(function(id){return R.mitre[id].tactic===tac}).sort();
    var box=el("div","tac"+(ids.length?" hit":"")); add(box, el("h3",null,tac));
    if(!ids.length) add(box, el("div","none","—"));
    ids.forEach(function(id){
      var fs=R.findings.filter(function(f){return f.mitre.indexOf(id)>=0});
      var s=maxSev(fs), t=el("button","tech"); t.type="button";
      var d=el("span","d"); d.style.background=cssv(VAR[s]);
      var lbl=el("span"); add(lbl, el("b",null,id+" · "+fs.length+"×"), R.mitre[id].name);
      add(t, d, lbl); t.title=fs.length+" finding(s), worst: "+s;
      t.addEventListener("click",function(){ FS.sev={critical:1,high:1,medium:1,low:1,info:1}; FS.mitre=id; drawFindings(); show("findings"); });
      box.appendChild(t);
    });
    grid.appendChild(box);
  });
  add(right, add(ac, ah, add(el("div","card-b"), grid)));

  /* by category */
  var cc=el("div","card"); add(cc, add(el("div","card-h"), el("h2",null,"Findings by area")));
  var cb=el("div","card-b");
  var cats={}; R.findings.forEach(function(f){ if(f.sev==="info") return;
    (cats[f.cat]=cats[f.cat]||{n:0,c:{}}).n++; cats[f.cat].c[f.sev]=(cats[f.cat].c[f.sev]||0)+1; });
  var keys=Object.keys(cats).sort(function(a,b){return cats[b].n-cats[a].n});
  if(!keys.length) add(cb, el("div","empty","Nothing above info level."));
  var mx=Math.max.apply(null,keys.map(function(k){return cats[k].n}).concat([1]));
  keys.forEach(function(k){
    var row=el("div","tbar"); var tr=el("div","track"); tr.style.display="flex"; tr.style.gap="2px";
    tr.style.width=(cats[k].n/mx*100)+"%"; tr.style.background="transparent";
    SEV.slice(0,4).forEach(function(s){ var n=cats[k].c[s]; if(!n) return; var sp=el("span");
      sp.style.flex=String(n); sp.style.background=cssv(VAR[s]); sp.title=n+" "+s; tr.appendChild(sp); });
    var wrapT=el("div"); wrapT.appendChild(tr);
    var b2=el("button","tech"); b2.type="button"; b2.style.padding="0"; add(b2, el("span",null,CAT[k]||k));
    b2.addEventListener("click",function(){ FS.cat=k; FS.mitre=""; drawFindings(); show("findings"); });
    add(row, b2, wrapT, el("span","s",cats[k].n)); cb.appendChild(row);
  });
  add(right, add(cc, cb));
  if(R.intel){ var ic=el("div","card"); add(ic, add(el("div","card-h"), el("h2",null,"Threat intel")));
    var ib=el("div","card-b"); intelSummary(ib); add(right, add(ic, ib)); }
  add(g, left, right); p.appendChild(g);
}

/* ================= findings ================= */
var FS={sev:{critical:1,high:1,medium:1,low:1}, cat:"", q:"", mitre:""};
function evRows(tb, obj){
  Object.keys(obj).forEach(function(k){
    var v=obj[k]; if(v===null||v===undefined||v==="") return;
    var tr=el("tr"), th=el("th",null,k), td=el("td");
    if(Array.isArray(v)){ v.forEach(function(x){ add(td, el("div",null,typeof x==="object"?JSON.stringify(x):x)); }); }
    else if(typeof v==="object"){ Object.keys(v).forEach(function(kk){ add(td, el("div",null,kk+"  "+JSON.stringify(v[kk]))); }); }
    else if(typeof v==="string" && /^https:\/\/www\.virustotal\.com\//.test(v)){
      var a=el("a",null,v); a.href=v; a.target="_blank"; a.rel="noopener noreferrer"; add(td,a); }
    else { add(td, String(v)); if(k==="sha256"||k==="fingerprint") add(td, copyBtn(String(v))); }
    add(tb, add(tr, th, td));
  });
}
function findingCard(f){
  var d=el("details","fd "+f.sev); d.id="f-"+f.id; if(f.sev==="critical") d.open=true;
  var s=el("summary"), m=el("div","fd-m");
  add(m, el("span","tag",CAT[f.cat]||f.cat), el("span","tag mono",f.check));
  f.mitre.forEach(function(id){ add(m, mitreChip(id)); });
  add(s, sevBadge(f.sev), el("div","fd-t",f.title), el("span","fd-x","▸"), m);
  var b=el("div","fd-b");
  if(f.why) add(b, el("p",null,f.why));
  if(f.fix) add(b, el("p","fix",f.fix));
  var tb=el("table","kv"); evRows(tb, f.evidence); add(b, tb);
  add(d, s, b); return d;
}
function drawFindings(){
  var p=document.getElementById("p-findings"); p.innerHTML=""; drawn.findings=1;
  var bar=el("div","filters");
  SEV.forEach(function(s){
    var n=R.findings.filter(function(f){return f.sev===s}).length;
    var c=el("button","chip"); c.type="button"; c.setAttribute("aria-pressed",FS.sev[s]?"true":"false");
    var d=el("span","d"); d.style.background=cssv(VAR[s]); add(c, d, s, el("span","c",n));
    c.addEventListener("click",function(){ if(FS.sev[s]) delete FS.sev[s]; else FS.sev[s]=1; drawFindings(); });
    bar.appendChild(c);
  });
  var sel=el("select","inp"); add(sel, el("option",null,"all areas")); sel.firstChild.value="";
  Object.keys(CAT).forEach(function(k){ if(!R.findings.some(function(f){return f.cat===k})) return;
    var o=el("option",null,CAT[k]); o.value=k; if(FS.cat===k) o.selected=true; sel.appendChild(o); });
  sel.addEventListener("change",function(){ FS.cat=sel.value; drawFindings(); });
  var q=el("input","inp grow"); q.type="search"; q.placeholder="search titles and evidence…"; q.value=FS.q;
  q.setAttribute("aria-label","Search findings");
  q.addEventListener("input",function(){ FS.q=q.value; list(); });
  add(bar, sel, q);
  if(FS.mitre){ var mc=el("button","chip",FS.mitre+"  ✕"); mc.type="button"; mc.setAttribute("aria-pressed","true");
    mc.addEventListener("click",function(){ FS.mitre=""; drawFindings(); }); bar.appendChild(mc); }
  var expand=el("button","btn","expand all"); expand.type="button";
  expand.addEventListener("click",function(){ var o=expand.textContent==="expand all";
    box.querySelectorAll("details").forEach(function(d){d.open=o}); expand.textContent=o?"collapse all":"expand all"; });
  add(bar, expand);
  var cnt=el("div","cnt"); var box=el("div");
  add(p, bar, cnt, box);
  function list(){
    box.innerHTML=""; var ql=FS.q.toLowerCase(), n=0;
    R.findings.forEach(function(f){
      if(!FS.sev[f.sev]) return; if(FS.cat && f.cat!==FS.cat) return;
      if(FS.mitre && f.mitre.indexOf(FS.mitre)<0) return;
      if(ql && (f.title+" "+f.check+" "+JSON.stringify(f.evidence)).toLowerCase().indexOf(ql)<0) return;
      box.appendChild(findingCard(f)); n++;
    });
    cnt.textContent=n+" of "+R.findings.length+" findings"; cnt.style.margin="0 0 10px";
    if(!n) add(box, el("div","empty","No findings match these filters."));
  }
  list();
}
function openFinding(id){
  var f=R.findings.filter(function(x){return x.id===id})[0]; if(!f) return;
  FS.sev={critical:1,high:1,medium:1,low:1,info:1}; FS.cat=""; FS.q=""; FS.mitre="";
  drawFindings(); show("findings");
  var d=document.getElementById("f-"+id);
  if(d){ d.open=true; d.scrollIntoView({block:"center"}); d.classList.add("flash"); }
}

/* ================= generic inventory tables ================= */
function isHot(flags){ return (flags||[]).some(function(x){ return !WEAK[x]; }); }
/* display order: the columns an analyst reads first; anything not listed keeps its place after */
var COLORDER = {
  connections:["direction","process","pid","user","remote","rport","location","ip VT","exe VT","state","local","parent","exe","package","cmdline","sha256","proto","flags"],
  listeners:["proto","addr","port","comm","pid","user","exe VT","exe","package","cmdline","sha256","flags"],
  processes:["pid","ppid","user","comm","exe","virustotal","package","flags","cmdline","started","cpu%","rss_kb","sha256"],
  logins:["user","from","location","ip VT","method","count","first","last","failures from source","flags"],
  failed_logins:["source","failures","location","ip VT","users tried"],
  services:["unit","default","reason","enabled","running","exec path","exec package","exec VT","exec sha256","scope","exec targets","unit file","unit package","changed","flags"],
  services_nondefault:["unit","reason","enabled","running","exec path","exec package","exec VT","exec sha256","scope","exec targets","unit file","unit package","changed","flags","default"],
  cron:["source","user","schedule","command","default","reason","exec path","exec package","exec VT","exec sha256","exec targets","file package","flags"],
  cron_nondefault:["source","user","schedule","command","reason","exec path","exec package","exec VT","exec sha256","exec targets","file package","flags","default"]};
function colOrder(key, cols){
  var pref=COLORDER[key]||[], out=[];
  pref.forEach(function(n){ var i=cols.indexOf(n); if(i>=0) out.push(i); });
  cols.forEach(function(_,i){ if(out.indexOf(i)<0) out.push(i); });
  return out;
}
function invCard(key, inv, rowsOverride, opts){
  opts=opts||{};
  var rows=(rowsOverride||inv.rows).slice(), cols=inv.cols, fi=cols.indexOf("flags");
  var c=el("div","card"), h=el("div","card-h"), tools=el("div","sec-tools");
  var hot=rows.filter(function(r){ return fi>=0 && isHot(r[fi]); }).length;
  var cn=el("span","cnt", rows.length+" row"+(rows.length===1?"":"s")+(hot?" · "+hot+" flagged":""));
  var q=el("input","inp"); q.type="search"; q.placeholder="filter"; q.size=18; q.setAttribute("aria-label","Filter "+inv.title);
  add(tools, cn, q); add(h, el("h2",null,opts.title||inv.title), tools); c.appendChild(h);
  if(inv.note) add(c, add(el("div","card-b"), el("p","note",inv.note)));
  if(!rows.length){ add(c, add(el("div","card-b"), el("div","empty","Nothing recorded."))); return c; }
  var wrap=el("div","tw"), t=el("table","t"), thead=el("thead"), tb=el("tbody"), trh=el("tr");
  var limit=200, sortI=-1, dir=1, view=rows, order=colOrder(key, cols);
  if(fi>=0) rows.sort(function(a,b){ return (isHot(b[fi])?1:0)-(isHot(a[fi])?1:0); });
  order.forEach(function(i){
    var cname=cols[i], th=el("th",null,cname); th.scope="col";
    th.addEventListener("click",function(){
      dir = sortI===i ? -dir : 1; sortI=i;
      trh.querySelectorAll("th").forEach(function(x){x.removeAttribute("aria-sort")});
      th.setAttribute("aria-sort",dir===1?"ascending":"descending");
      view.sort(function(a,b){ var x=a[i],y=b[i];
        if(typeof x==="number"&&typeof y==="number") return (x-y)*dir;
        return String(x===null?"":x).localeCompare(String(y===null?"":y),undefined,{numeric:true})*dir; });
      body();
    });
    trh.appendChild(th);
  });
  add(t, add(thead,trh), tb); wrap.appendChild(t); c.appendChild(wrap);
  var more=el("button","more"); more.type="button";
  more.addEventListener("click",function(){ limit=1e9; body(); });
  c.appendChild(more);
  function body(){
    tb.innerHTML="";
    view.slice(0,limit).forEach(function(r){
      var tr=el("tr");
      if(opts.rowFn) tr.className=opts.rowFn(r);
      else if(fi>=0 && isHot(r[fi])) tr.className="hot";
      order.forEach(function(i){
        var v=r[i], td=el("td");
        if(/sha256$/.test(cols[i]) && typeof v==="string" && v.length===64){
          td.title=v; add(td, v.slice(0,12)+"\u2026"); add(td, copyBtn(v)); td.style.whiteSpace="nowrap"; }
        else if(cols[i]==="cmdline" || cols[i]==="command"){
          var cl=el("div","clamp",String(v||"").replace(/\s*[\r\n]+\s*/g," \u23CE ")); td.appendChild(cl);
          td.style.maxWidth="340px"; td.style.minWidth="200px"; td.title=v||""; }
        else if(cols[i]==="reason" || cols[i]==="unit" || cols[i]==="source"){
          td.textContent=v||""; td.style.minWidth=(cols[i]==="reason"?"240px":"170px"); }
        else if(cols[i]==="location"){ td.textContent=v||""; td.style.minWidth="230px"; }
        else if(/VT$|^virustotal$/.test(cols[i]) && typeof v==="string" && !/^https/.test(v)){
          td.textContent=v; td.style.whiteSpace="nowrap";
          if(/^([2-9]|\d\d+)\//.test(v)) td.style.color="var(--crit)"; }
        else if(i===fi){ (v||[]).forEach(function(x){ add(td, el("span","pill"+(WEAK[x]?"":" hot"),x)); }); }
        else if(Array.isArray(v)){ v.forEach(function(x){ add(td, el("div",null,x)); }); td.style.whiteSpace="nowrap"; }
        else if(typeof v==="string" && /^https:\/\/www\.virustotal\.com\//.test(v)){
          var a=el("a","chipm","open \u2197"); a.href=v; a.target="_blank"; a.rel="noopener noreferrer"; td.appendChild(a); }
        else { if(typeof v==="number") td.className="num"; td.textContent=(v===null||v===undefined)?"":String(v); }
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    });
    more.style.display = view.length>limit ? "" : "none";
    more.textContent = "show all "+view.length+" rows";
  }
  q.addEventListener("input",function(){ var s=q.value.toLowerCase();
    view = s ? rows.filter(function(r){ return JSON.stringify(r).toLowerCase().indexOf(s)>=0; }) : rows.slice();
    cn.textContent=view.length+" of "+rows.length+" rows"; body(); });
  body();
  return c;
}
var ORDER={network:["listeners","connections","raw_sockets","interfaces"],
  persistence:["services_nondefault","cron_nondefault","immutable","containers","persistence_more","services","cron","at_jobs","autostart","shell_init","pam","ld_so_conf","systemd"],
  accounts:["sessions","session_history","users","logins","failed_logins","account_events","ssh_keys","sshd_config","sudoers","history"],
  intel:["intel_vt","intel_geo"],
  system:["dpkg_verify","modules","bin_unpackaged","conffiles","suid","caps","dropped","webshells","recent_changes","logfiles","bpf_pins"]};
function drawInv(tab){
  var p=document.getElementById("p-"+tab), keys=invByTab[tab].slice();
  var ord=ORDER[tab]||[];
  keys.sort(function(a,b){ var x=ord.indexOf(a), y=ord.indexOf(b); return (x<0?99:x)-(y<0?99:y); });
  var cats={network:["network"],persistence:["persistence"],accounts:["accounts","logs"],system:["kernel","integrity","filesystem"],intel:["intel"]}[tab];
  var rel=R.findings.filter(function(f){ return cats.indexOf(f.cat)>=0 && f.sev!=="info"; });
  if(rel.length){
    var c=el("div","card"), h=el("div","card-h"); add(h, el("h2",null,"Findings in this area"), el("span","cnt",rel.length));
    var b=el("div","card-b");
    rel.slice(0,12).forEach(function(f){ var r=el("div","tf"); r.addEventListener("click",function(){openFinding(f.id)});
      add(r, sevBadge(f.sev), el("div","tf-t",f.title)); b.appendChild(r); });
    if(rel.length>12) add(b, el("div","cnt","+ "+(rel.length-12)+" more in Findings"));
    add(p, add(c,h,b));
  }
  keys.forEach(function(k){ p.appendChild(invCard(k, R.inventory[k])); });
}

/* ================= threat intel ================= */
function intelSummary(box){
  var I=R.intel, dl=el("dl","facts");
  [["Public IPs", I.public_ips],["Geolocation", I.geo_provider||"off"],
   ["VirusTotal files", I.virustotal?(I.vt_files.looked_up+" looked up \u00b7 "+I.vt_files.malicious+" flagged by 2+ engines \u00b7 "+I.vt_files.unknown+" unknown"):"not queried"],
   ["VirusTotal IPs", I.virustotal?(I.vt_ips.looked_up+" looked up \u00b7 "+I.vt_ips.malicious+" flagged by 2+ engines"):"not queried"],
   ["Enriched", fmt(I.generated)]].forEach(function(x){ add(dl, el("dt",null,x[0]), el("dd",null,x[1])); });
  box.appendChild(dl);
  if((I.countries||[]).length){
    var mx=I.countries[0].ips, wrap=el("div"); wrap.style.marginTop="14px";
    add(wrap, el("div","k-label","Public IPs by country"));
    I.countries.slice(0,12).forEach(function(c){
      var row=el("div","tbar"), tr=el("div","track"), sp=el("span"); sp.style.width=(c.ips/mx*100)+"%";
      sp.style.background="var(--low)"; tr.appendChild(sp);
      var nm=el("span"); add(nm, el("span","chipm",c.cc), " "+c.country);
      add(row, nm, tr, el("span","s",c.ips)); wrap.appendChild(row); });
    box.appendChild(wrap);
  }
  (I.notes||[]).forEach(function(n){ add(box, el("p","note",n)); });
}
function drawIntelHead(){
  var p=document.getElementById("p-intel"), c=el("div","card");
  add(c, add(el("div","card-h"), el("h2",null,"Threat intelligence"),
    el("span","cnt","added on the analysis machine \u00b7 hash and IP lookups only, nothing uploaded")));
  var b=el("div","card-b"); intelSummary(b); add(p, add(c,b));
}

/* ================= processes ================= */
function drawProcesses(){
  var p=document.getElementById("p-processes"), inv=R.inventory.processes; if(!inv) return;
  var rows=inv.rows, by={}, kids={};
  rows.forEach(function(r){ by[r[0]]=r; });
  rows.forEach(function(r){ var pp=by[r[1]]?r[1]:0; (kids[pp]=kids[pp]||[]).push(r); });
  var c=el("div","card"), h=el("div","card-h"), tools=el("div","sec-tools");
  var kt=el("label","cnt"); var kcb=el("input"); kcb.type="checkbox"; kcb.checked=true; add(kt, kcb, " hide kernel threads");
  var fl=el("label","cnt"); var fcb=el("input"); fcb.type="checkbox"; add(fl, fcb, " flagged only");
  var q=el("input","inp"); q.type="search"; q.placeholder="filter"; q.size=18; q.setAttribute("aria-label","Filter processes");
  add(tools, kt, fl, q); add(h, el("h2",null,"Process tree"), tools);
  var tree=el("div","ptree"); add(c, h, tree); p.appendChild(c);
  function hot(r){ return isHot(r[10]); }
  function keep(){
    var s=q.value.toLowerCase(), want={};
    rows.forEach(function(r){
      if(kcb.checked && r[9]==="kthread") return;
      var ok=(!fcb.checked||hot(r)) && (!s||(r[3]+" "+r[4]+" "+r[5]+" "+r[2]+" "+r[0]).toLowerCase().indexOf(s)>=0);
      if(ok){ var x=r; while(x && !want[x[0]]){ want[x[0]]=1; x=by[x[1]]; } }
    });
    return want;
  }
  function draw(){
    tree.innerHTML=""; var want=keep(), n=0;
    (function walk(pp, depth, prefix){
      var list=(kids[pp]||[]).filter(function(r){ return want[r[0]] && r[0]!==pp; });
      list.forEach(function(r,i){
        var last=i===list.length-1, row=el("div","pr"+(hot(r)?" hot":"")+((r[10]||[]).indexOf("analyst-session")>=0?" me":""));
        var line=el("div","line");
        add(line, el("span","guide",prefix+(depth?(last?"└─ ":"├─ "):"")),
            el("span","pid",String(r[0]).padStart(6)+" "), el("span","usr",(r[2]||"").padEnd(10)+" "),
            el("span","cm",String(r[5]||r[3]).replace(/\s*[\r\n]+\s*/g," \u23CE ")));
        (r[10]||[]).forEach(function(x){ add(line, " ", el("span","pill"+(WEAK[x]?"":" hot"),x)); });
        row.title="exe: "+(r[4]||"-")+"\nstarted: "+r[6]+"\npackage: "+(r[9]||"-")+(r[7]!==null?"\ncpu: "+r[7]+"%":"")+
          (r[11]?"\nsha256: "+r[11]:"")+(r[12]?"\nVirusTotal: "+r[12]:"");
        add(row, line); tree.appendChild(row); n++;
        walk(r[0], depth+1, prefix+(depth?(last?"   ":"│  "):""));
      });
    })(0,0,"");
    if(!n) add(tree, el("div","empty","No processes match."));
  }
  [kcb,fcb].forEach(function(x){x.addEventListener("change",draw)}); q.addEventListener("input",draw);
  draw();
  p.appendChild(invCard("processes", inv, null, {title:"Process table"}));
}

/* ================= evidence ================= */
function drawEvidence(){
  var p=document.getElementById("p-evidence"), c=el("div","card"), h=el("div","card-h");
  add(h, el("h2",null,"Collected and hashed files"), el("span","cnt",R.evidence.length+" files"));
  c.appendChild(h);
  add(c, add(el("div","card-b"), el("p","note","Samples are copied into the case folder's evidence/ directory as read-only *.sample files (never executable). HASHES.txt in the case folder covers this report, triage.json and every sample.")));
  if(!R.evidence.length){ add(c, add(el("div","card-b"), el("div","empty","No files needed collecting."))); p.appendChild(c); return; }
  var wrap=el("div","tw"), t=el("table","t"), tb=el("tbody"), tr=el("tr");
  ["file","reason","size","sha256","saved as"].forEach(function(x){ tr.appendChild(el("th",null,x)); });
  add(t, add(el("thead"),tr), tb);
  R.evidence.forEach(function(e){
    var r=el("tr"); add(r, el("td",null,e.path), el("td",null,e.why), add(el("td","num"), String(e.size)));
    var td=el("td"); add(td, e.sha256||"—"); if(e.sha256) add(td, copyBtn(e.sha256)); r.appendChild(td);
    add(r, el("td",null,e.saved||e.error||"hashed only")); tb.appendChild(r);
  });
  add(c, add(wrap,t)); p.appendChild(c);
}

/* ================= changes ================= */
function drawChanges(){
  var p=document.getElementById("p-changes");
  if(!DIFF){ var c0=el("div","card"); add(c0, add(el("div","card-h"), el("h2",null,"Changes since an earlier triage")),
      add(el("div","card-b"), el("p",null,"No baseline was given. Run the triage again with --compare old/triage.json (or render with procsnap_viz.py new.json --compare old.json) to see new and resolved findings and every inventory change — against an earlier run of this host, or a known-good host of the same role.")));
    p.appendChild(c0); return; }
  add(p, el("p","note","Compared with "+(D.base.host||"?")+" triaged "+fmt(D.base.started)+"."));
  [["New findings",DIFF.findings["new"]],["Resolved findings",DIFF.findings.gone]].forEach(function(x){
    var c=el("div","card"), h=el("div","card-h"); add(h, el("h2",null,x[0]), el("span","cnt",x[1].length)); c.appendChild(h);
    var b=el("div","card-b"); if(!x[1].length) add(b, el("div","empty","None."));
    x[1].sort(function(a,b){return SEV.indexOf(a.sev)-SEV.indexOf(b.sev)}).forEach(function(f){
      var r=el("div","tf"); add(r, sevBadge(f.sev), el("div","tf-t",f.title)); b.appendChild(r); });
    add(c,b); p.appendChild(c);
  });
  Object.keys(DIFF.inventory).forEach(function(k){
    var x=DIFF.inventory[k];
    var rows=x.added.map(function(r){return ["+"].concat(r)}).concat(x.removed.map(function(r){return ["−"].concat(r)}));
    var inv={title:x.title+"  (+"+x.added.length+" / −"+x.removed.length+")", cols:["±"].concat(x.cols), rows:rows};
    p.appendChild(invCard(k, inv, null, {rowFn:function(r){ return r[0]==="+"?"diffrow-add":"diffrow-rem"; }}));
  });
}

/* ================= run info ================= */
function drawRun(){
  var p=document.getElementById("p-run"), g=el("div","grid2"), l=el("div"), r=el("div");
  var c=el("div","card"); add(c, add(el("div","card-h"), el("h2",null,"Check timings"), el("span","cnt","total "+R.duration_s+"s")));
  var b=el("div","card-b"), mx=Math.max.apply(null,Object.keys(R.timings).map(function(k){return R.timings[k]}).concat([0.01]));
  Object.keys(R.timings).forEach(function(k){ var row=el("div","tbar"), tr=el("div","track"), sp=el("span");
    sp.style.width=Math.max(1,R.timings[k]/mx*100)+"%"; tr.appendChild(sp);
    add(row, el("span",null,k), tr, el("span","s",R.timings[k]+"s")); b.appendChild(row); });
  add(l, add(c,b));
  var c2=el("div","card"); add(c2, add(el("div","card-h"), el("h2",null,"Notes and errors"), el("span","cnt",R.errors.length)));
  var b2=el("div","card-b"); if(!R.errors.length) add(b2, el("div","empty","Every check completed."));
  var ul=el("ul","lim"); R.errors.forEach(function(e){ add(ul, add(el("li"), el("b",null,e.check+": "), e.error)); }); add(b2, ul);
  add(l, add(c2,b2));
  var c3=el("div","card"); add(c3, add(el("div","card-h"), el("h2",null,"Run parameters")));
  var dl=el("dl","facts");
  [["Root",R.options.root],["Recent window",R.options.days+" days"],["Deep mode",R.options.deep?"yes":"no"],
   ["Evidence copied",R.options.collect?"yes":"hashes only"],["Sweep budget",R.options.walk_budget+"s"],
   ["Tool version",R.version],["Tool SHA-256",R.self.sha256||"?"],["Command",(R.self.argv||[]).join(" ")]].forEach(function(x){
    add(dl, el("dt",null,x[0]), el("dd","mono",x[1])); });
  add(r, add(c3, add(el("div","card-b"), dl)));
  var c4=el("div","card"); add(c4, add(el("div","card-h"), el("h2",null,"Limits — state these in the case notes")));
  var ul2=el("ul","lim");
  ["Everything here is read through the running kernel. A kernel rootkit can hide from /proc; the hidden-PID, hidden-module and package-checksum checks catch common ones, not good ones. For certainty, acquire memory (AVML + Volatility) and image the disk.",
   "A live triage is a single point in time. Short-lived processes and connections are only seen by the continuous collector (procsnap collect) or auditd/eBPF.",
   "Unpackaged does not mean malicious: vendor agents, /usr/local software and containers are normal. Findings say why each item matters; the analyst decides.",
   "Local logs (auth.log, wtmp, history) are attacker-writable on a root-compromised host. Prefer off-host copies.",
   "The analyst's own shell session is excluded from process findings and marked 'analyst-session'."].forEach(function(t){ add(ul2, el("li",null,t)); });
  add(r, add(c4, add(el("div","card-b"), ul2)));
  add(g,l,r); p.appendChild(g);
}

var DRAW={overview:drawOverview, findings:drawFindings, processes:drawProcesses,
  network:function(){drawInv("network")}, persistence:function(){drawInv("persistence")},
  accounts:function(){drawInv("accounts")}, system:function(){drawInv("system")},
  intel:function(){ drawIntelHead(); drawInv("intel"); },
  evidence:drawEvidence, changes:drawChanges, run:drawRun};
document.getElementById("foot").textContent = (H.hostname||"?")+" · "+fmt(R.started)+" · verdict: "+R.verdict.text;

/* theme + print */
(function(){
  var root=document.documentElement, KEY="procsnap-theme";
  try{ var t=localStorage.getItem(KEY); if(t) root.setAttribute("data-theme",t); }catch(_){}
  document.getElementById("theme").addEventListener("click",function(){
    var dark = root.getAttribute("data-theme") ? root.getAttribute("data-theme")==="dark"
             : matchMedia("(prefers-color-scheme: dark)").matches;
    var n = dark ? "light" : "dark"; root.setAttribute("data-theme", n);
    try{ localStorage.setItem(KEY,n); }catch(_){}
  });
  document.getElementById("print").addEventListener("click",function(){
    Object.keys(DRAW).forEach(function(k){ if(!drawn[k]){ drawn[k]=1; DRAW[k](); } });
    document.querySelectorAll("details.fd").forEach(function(d){d.open=true});
    window.print();
  });
})();
var start=(location.hash||"").slice(1);
show(DRAW[start]?start:"overview");
</script>
</body></html>
"""


def main():
    ap = argparse.ArgumentParser(
        description="render procsnap output as a single self-contained HTML report",
        epilog="A triage.json (from 'procsnap.py triage') gives the triage report; a JSONL "
               "log directory (from 'procsnap.py collect') gives the timeline report.")
    ap.add_argument("path", help="collector log dir/file, or a triage.json")
    ap.add_argument("-o", "--out", default=None,
                    help="output file (default procsnap-report.html / triage.html next to the json)")
    ap.add_argument("--since", help="timeline only: 30m / 2h / 7d / 'YYYY-MM-DD HH:MM'")
    ap.add_argument("--title", default=None)
    ap.add_argument("--compare", metavar="OLD.json", help="triage only: baseline triage.json")
    a = ap.parse_args()
    ps.protect_console()

    if a.path.endswith(".json") and os.path.isfile(a.path):
        with open(a.path) as fh:
            res = json.load(fh)
        if res.get("kind") != "triage":
            raise SystemExit(f"{a.path} is not a procsnap triage.json")
        base = None
        if a.compare:
            with open(a.compare) as fh:
                base = json.load(fh)
        out = a.out or os.path.join(os.path.dirname(os.path.abspath(a.path)), "triage.html")
        page = render_triage(res, base)
        with open(out, "w") as fh:
            fh.write(page)
        c = res["counts"]
        print(f"wrote {out}  ({len(page)//1024} KB)  verdict: {res['verdict']['text']}  "
              f"[{c['critical']} critical, {c['high']} high, {c['medium']} medium]")
        return
    a.out = a.out or "procsnap-report.html"

    since = ps.parse_since(a.since) if a.since else None
    data = build(a.path, since)
    title = a.title or f"procsnap · {data['meta']['host']}"
    page = fill(TEMPLATE, data, TITLE=title, VERSION=ps.VERSION)
    with open(a.out, "w") as fh:
        fh.write(page)
    m = data["meta"]
    print(f"wrote {a.out}  ({len(page)//1024} KB)")
    print(f"  host {m['host']} · {m['starts']} execs · "
          f"{len(data['dests'])} dest pairs · {len(data['listeners'])} listeners")
    hi = sum(len(v) for v in data["findings"]["high"].values())
    print(f"  {hi} high-severity flag events")


if __name__ == "__main__":
    main()
