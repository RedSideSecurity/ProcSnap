#!/usr/bin/env python3
"""
procsnap_analyze - analysis-workstation side of ProcSnap.

Takes a case collected on a suspect host (scripts/collect_case.sh archive, a case
directory, or a bare triage.json), enriches it with threat intelligence, and writes
the reports:

    ./procsnap_analyze.py procsnap-web01-20261103T061500Z.tar.gz
    ./procsnap_analyze.py case.tar.gz --vt-key "$VT_API_KEY"         # + VirusTotal
    ./procsnap_analyze.py case.tar.gz --geo ipinfo --ipinfo-token T    # other geo source
    ./procsnap_analyze.py case-dir/ --offline                          # no lookups at all

Enrichment
  * Geolocation + ASN of every public IP (connections, login and brute-force sources,
    collector connections). Default provider: ip-api.com (free, no key, batched).
  * VirusTotal (with --vt-key or VT_API_KEY): reputation of every executable SHA-256
    (running processes, collector process starts, collected evidence) and of every
    public IP. HASH/IP LOOKUPS ONLY: nothing is ever uploaded.

Lookups run here, on the analysis machine, never on the target. Results are cached in
~/.cache/procsnap so re-running a report costs no quota. The original triage.json is
never modified: the enriched copy is written next to the reports.

Standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
from http.client import HTTPException
import ipaddress
import json
import os
import re
import sys
import shutil
import tarfile
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import procsnap as ps          # noqa: E402
import procsnap_viz as viz     # noqa: E402

VT_URL = os.environ.get("PROCSNAP_VT_URL", "https://www.virustotal.com/api/v3")
IPAPI_URL = os.environ.get("PROCSNAP_IPAPI_URL", "http://ip-api.com/batch")
IPINFO_URL = os.environ.get("PROCSNAP_IPINFO_URL", "https://api.ipinfo.io/lite")
CACHE_DIR = os.environ.get("PROCSNAP_CACHE",
                           os.path.join(os.path.expanduser("~"), ".cache", "procsnap"))
UA = f"procsnap-analyze/{ps.VERSION}"
MAX_EXTRACT = int(os.environ.get("PROCSNAP_MAX_EXTRACT_GB", "8")) << 30
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TTL = {"geo": 30 * 86400, "vt_file": 2 * 86400, "vt_ip": 2 * 86400}


def say(msg, quiet=False):
    if not quiet:
        print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# case loading (archives from the target are untrusted input)
# --------------------------------------------------------------------------
def safe_extract(archive, dest):
    """Extract a .tar.gz without trusting it: no absolute paths, no '..', no links,
    no devices, and nothing made executable (the evidence samples are malware)."""
    total = 0
    with tarfile.open(archive, "r:*") as tf:
        for n_, m in enumerate(tf):
            if n_ > 500000:
                raise SystemExit("refusing archive: more than 500000 members")
            name = m.name
            while name.startswith("./"):              # only the "./" prefix, never ".hidden"
                name = name[2:]
            if not name or name == ".":
                continue
            if m.name.startswith("/") or ".." in m.name.split("/"):
                raise SystemExit(f"refusing unsafe path in archive: {m.name!r}")
            target = os.path.realpath(os.path.join(dest, name))
            if not target.startswith(os.path.realpath(dest) + os.sep):
                raise SystemExit(f"refusing path outside destination: {m.name!r}")
            if m.isdir():
                os.makedirs(target, mode=0o700, exist_ok=True)
            elif m.isfile():
                os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
                if os.path.lexists(target):            # duplicate member: last one wins
                    os.chmod(target, 0o600)
                    os.unlink(target)
                src = tf.extractfile(m)
                with open(target, "wb") as out:
                    while True:
                        b = src.read(1 << 20)
                        if not b:
                            break
                        total += len(b)
                        if total > MAX_EXTRACT:
                            raise SystemExit(f"refusing archive: expands beyond "
                                             f"{MAX_EXTRACT >> 30} GiB (decompression bomb?)")
                        out.write(b)
                os.chmod(target, 0o400 if name.endswith(".sample") else 0o600)
            # symlinks, hardlinks, devices, fifos: skipped on purpose


def open_case(path, workdir):
    """-> (case_dir, triage_json_path or None, collector_dir or None, case_meta)"""
    if os.path.isfile(path) and (path.endswith((".tar.gz", ".tgz", ".tar"))):
        safe_extract(path, workdir)
        path = workdir
    if os.path.isfile(path) and path.endswith(".json"):
        return os.path.dirname(os.path.abspath(path)), path, None, {}
    if not os.path.isdir(path):
        raise SystemExit(f"{path}: not a case archive, case directory or triage.json")
    triage = coll = None
    meta = {}
    for dp, dn, fn in os.walk(path):
        dn.sort()
        if "triage.json" in fn and triage is None:
            triage = os.path.join(dp, "triage.json")
        if coll is None and any(re.match(r"procsnap-\d{8}\.jsonl(\.gz)?$", f) for f in fn):
            coll = dp
        if "case.json" in fn and not meta:
            try:
                with open(os.path.join(dp, "case.json")) as fh:
                    meta = json.load(fh)
            except (OSError, ValueError):
                pass
    if not triage and not coll:
        raise SystemExit(f"{path}: no triage.json and no collector logs found")
    return path, triage, coll, meta


# --------------------------------------------------------------------------
# cache + HTTP
# --------------------------------------------------------------------------
class Cache:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.data = {}
        self.path = os.path.join(CACHE_DIR, "intel-cache.json")
        if enabled:
            try:
                with open(self.path) as fh:
                    self.data = json.load(fh)
            except (OSError, ValueError):
                self.data = {}

    def get(self, kind, key):
        e = self.data.get(kind, {}).get(key)
        if e and time.time() - e["ts"] < TTL[kind]:
            return e["v"]
        return None

    def put(self, kind, key, value):
        self.data.setdefault(kind, {})[key] = {"ts": time.time(), "v": value}

    def save(self):
        if not self.enabled:
            return
        os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(self.data, fh)
        os.replace(tmp, self.path)


class HTTPError(Exception):
    def __init__(self, code, body=""):
        super().__init__(f"HTTP {code}")
        self.code, self.body = code, body


def http(url, data=None, headers=None, timeout=30):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace") or "null")
    except urllib.error.HTTPError as e:
        raise HTTPError(e.code, e.read()[:300].decode("utf-8", "replace")) from None


# --------------------------------------------------------------------------
# what to look up
# --------------------------------------------------------------------------
def norm_ip(ip):
    """-> canonical text of a PUBLIC address, else None. Only this normalised form is
    ever put into a lookup URL (no '%zone', no path tricks from a crafted case)."""
    try:
        a = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return None
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return str(a) if (a.is_global and not a.is_multicast) else None


def public_ip(ip):
    return norm_ip(ip) is not None


def valid_sha(s):
    return isinstance(s, str) and bool(SHA256_RE.match(s))


def _col(inv, name):
    return inv["cols"].index(name) if name in inv["cols"] else None


def gather(res, coll_dir):
    """-> ips {ip: {sources}}, hashes {sha: {"paths", "sources", "packaged"}}"""
    ips = defaultdict(set)
    hashes = defaultdict(lambda: {"paths": set(), "sources": set(), "packaged": False,
                                  "running": False, "net": False, "persist": False})
    inv = (res or {}).get("inventory", {})
    for name, col, label in (("connections", "remote", "connection"),
                             ("logins", "from", "login"),
                             ("failed_logins", "source", "failed login")):
        t = inv.get(name)
        i = _col(t, col) if t else None
        if i is None:
            continue
        for r in t["rows"]:
            ip = norm_ip(r[i])
            if ip:
                ips[ip].add(label)
    for name, sc, ec, pc, label in (("services", "exec sha256", "exec path", "exec package", "service"),
                                    ("cron", "exec sha256", "exec path", "exec package", "cron job")):
        t = inv.get(name)
        if not t or _col(t, sc) is None:
            continue
        si, ei, pi, di = _col(t, sc), _col(t, ec), _col(t, pc), _col(t, "default")
        for r in t["rows"]:
            if r[si]:
                h = hashes[r[si]]
                h["paths"].add(r[ei])
                h["sources"].add(label)
                h["packaged"] = h["packaged"] or bool(r[pi])
                if di is not None and r[di] == "no":
                    h["persist"] = True
    for name in ("connections", "listeners"):
        t = inv.get(name)
        if not t or _col(t, "sha256") is None:
            continue
        si, ei, pi = _col(t, "sha256"), _col(t, "exe"), _col(t, "package")
        ri = _col(t, "remote")
        for r in t["rows"]:
            if r[si]:
                h = hashes[r[si]]
                h["paths"].add(r[ei])
                h["running"] = True
                h["packaged"] = h["packaged"] or bool(r[pi])
                h["sources"].add("network process")
                if name == "listeners" or (ri is not None and public_ip(r[ri])):
                    h["net"] = True
    t = inv.get("processes")
    if t and _col(t, "sha256") is not None:
        si, ei, pi = _col(t, "sha256"), _col(t, "exe"), _col(t, "package")
        for r in t["rows"]:
            if r[si]:
                h = hashes[r[si]]
                h["paths"].add(r[ei])
                h["sources"].add("running process")
                h["running"] = True
                h["packaged"] = h["packaged"] or bool(r[pi])
    for e in (res or {}).get("evidence", []):
        if e.get("sha256"):
            h = hashes[e["sha256"]]
            h["paths"].add(e["path"])
            h["sources"].add("collected evidence")
    for f in (res or {}).get("findings", []):
        s = f["evidence"].get("sha256")
        if isinstance(s, str) and len(s) == 64:
            h = hashes[s]
            h["paths"].add(f["evidence"].get("file") or f["evidence"].get("exe") or "?")
            h["sources"].add("finding")
    if coll_dir:
        for ev in ps.load(coll_dir):
            k = ev.get("ev")
            if k == "conn_open" and norm_ip(ev.get("raddr")):
                ips[norm_ip(ev.get("raddr"))].add("collector connection")
            elif k in ("proc_start", "exe_hash") and ev.get("sha256"):
                h = hashes[ev["sha256"]]
                h["paths"].add(ev.get("exe") or "?")
                h["sources"].add("collector process")
    for s in [s for s in hashes if not valid_sha(s)]:   # crafted case: never build URLs
        del hashes[s]
    pk = {s for s, h in hashes.items() if h["packaged"]}
    for s in pk:                         # a hash seen as packaged anywhere is packaged
        hashes[s]["packaged"] = True
    return ips, hashes


# --------------------------------------------------------------------------
# geolocation
# --------------------------------------------------------------------------
def geo_lookup(ips, provider, token, cache, quiet):
    out, todo = {}, []
    for ip in sorted(ips):
        c = cache.get("geo", f"{provider}:{ip}")
        if c is not None:
            out[ip] = c
        else:
            todo.append(ip)
    if todo:
        say(f"[geo] {len(todo)} IP(s) via {provider} ({len(out)} cached)", quiet)
    if provider == "ip-api":
        fields = "status,message,query,country,countryCode,regionName,city,isp,org,as,asname,proxy,hosting"
        for i in range(0, len(todo), 100):
            batch = todo[i:i + 100]
            if i:
                time.sleep(4.2)                     # free tier: 15 batch requests / minute
            rows = http(f"{IPAPI_URL}?fields={fields}", json.dumps(batch).encode(),
                        {"Content-Type": "application/json"})
            if not isinstance(rows, list):
                raise ValueError(f"unexpected ip-api answer: {str(rows)[:120]}")
            for r in rows:
                if not isinstance(r, dict):
                    continue
                if r.get("status") != "success":
                    continue
                g = {"country": r.get("country"), "cc": r.get("countryCode"),
                     "region": r.get("regionName"), "city": r.get("city"),
                     "asn": (r.get("as") or "").split(" ")[0], "org": r.get("org") or r.get("isp"),
                     "isp": r.get("isp"), "hosting": bool(r.get("hosting")),
                     "proxy": bool(r.get("proxy"))}
                out[r["query"]] = g
                cache.put("geo", f"{provider}:{r['query']}", g)
    elif provider == "ipinfo":
        if not token:
            raise SystemExit("--geo ipinfo needs --ipinfo-token (free at ipinfo.io)")
        for ip in todo:
            r = http(f"{IPINFO_URL}/{ip}?token={token}")
            g = {"country": r.get("country"), "cc": r.get("country_code"), "region": None,
                 "city": None, "asn": r.get("asn"), "org": r.get("as_name"),
                 "isp": r.get("as_domain"), "hosting": None, "proxy": None}
            out[ip] = g
            cache.put("geo", f"{provider}:{ip}", g)
    return out


# --------------------------------------------------------------------------
# VirusTotal (lookups only - never uploads)
# --------------------------------------------------------------------------
class VTStop(Exception):
    pass


class VT:
    def __init__(self, key, rate, cache, quiet, budget):
        self.key, self.cache, self.quiet, self.budget = key, cache, quiet, budget
        self.gap = 60.0 / max(rate, 0.1)
        self.last = 0.0
        self.calls = 0
        self.notes = []

    def _get(self, path):
        if self.calls >= self.budget:
            raise VTStop(f"--vt-max {self.budget} lookups reached")
        wait = self.last + self.gap - time.time()
        if wait > 0:
            time.sleep(wait)
        for attempt in (1, 2):
            self.last = time.time()
            self.calls += 1
            try:
                return http(f"{VT_URL}/{path}", headers={"x-apikey": self.key})
            except HTTPError as e:
                if e.code == 404:
                    return None
                if e.code in (401, 403):
                    raise VTStop(f"VirusTotal rejected the API key (HTTP {e.code})")
                if e.code == 429 and attempt == 1:
                    say("[vt] quota hit - waiting 60s", self.quiet)
                    time.sleep(60)
                    continue
                if e.code == 429:
                    raise VTStop("VirusTotal quota exhausted (HTTP 429) - daily limit?")
                raise VTStop(f"VirusTotal error HTTP {e.code}: {e.body[:120]}")
            except (urllib.error.URLError, OSError, HTTPException) as e:
                raise VTStop(f"VirusTotal unreachable: {e}")
            except ValueError as e:                   # proxy / captive-portal HTML page
                raise VTStop(f"VirusTotal returned something that is not JSON: {e}")
        return None

    @staticmethod
    def _stats(a):
        s = a.get("last_analysis_stats") or {}
        total = sum(v for k, v in s.items() if k in ("malicious", "suspicious", "undetected",
                                                      "harmless", "timeout"))
        return {"malicious": s.get("malicious", 0), "suspicious": s.get("suspicious", 0),
                "harmless": s.get("harmless", 0), "undetected": s.get("undetected", 0),
                "total": total, "reputation": a.get("reputation"),
                "last_analysis": a.get("last_analysis_date")}

    def file(self, sha):
        if not valid_sha(sha):
            return {"found": False}
        c = self.cache.get("vt_file", sha)
        if c is not None:
            return c
        r = self._get(f"files/{sha}")
        if r is None:
            v = {"found": False}
        else:
            a = (r.get("data") or {}).get("attributes") or {}
            v = dict(self._stats(a), found=True,
                     label=((a.get("popular_threat_classification") or {})
                            .get("suggested_threat_label")),
                     name=a.get("meaningful_name"), names=(a.get("names") or [])[:5],
                     type=a.get("type_description"), tags=(a.get("tags") or [])[:8],
                     first_seen=a.get("first_submission_date"))
        self.cache.put("vt_file", sha, v)
        return v

    def ip(self, ip):
        ip = norm_ip(ip)
        if not ip:
            return {"found": False}
        c = self.cache.get("vt_ip", ip)
        if c is not None:
            return c
        r = self._get(f"ip_addresses/{ip}")
        if r is None:
            v = {"found": False}
        else:
            a = (r.get("data") or {}).get("attributes") or {}
            v = dict(self._stats(a), found=True, as_owner=a.get("as_owner"),
                     asn=a.get("asn"), country=a.get("country"),
                     tags=(a.get("tags") or [])[:8])
        self.cache.put("vt_ip", ip, v)
        return v


# --------------------------------------------------------------------------
# enrichment -> findings + tables
# --------------------------------------------------------------------------
def fmt_ts(t):
    return time.strftime("%Y-%m-%d", time.gmtime(t)) if isinstance(t, (int, float)) and t else ""


def geo_str(g):
    if not g:
        return ""
    parts = [g.get("cc") or g.get("country") or "?"]
    if g.get("city"):
        parts.append(g["city"])
    if g.get("asn"):
        parts.append(str(g["asn"]))
    if g.get("org"):
        parts.append(g["org"][:40])
    return " · ".join(parts)


def recompute(res):
    ps.recount(res)


def add_finding(res, sev, check, title, why, fix, ev, key, mitre=()):
    fid = hashlib.sha1(f"{check}|{key}".encode()).hexdigest()[:12]
    if any(f["id"] == fid for f in res["findings"]):
        return
    res["findings"].append({"id": fid, "sev": sev, "cat": "intel", "check": check,
                            "title": title, "mitre": list(mitre), "why": why, "fix": fix,
                            "evidence": ev})


def enrich(res, ips, hashes, geo, vt_files, vt_ips, intel_meta):
    inv = res["inventory"]
    # ---- VirusTotal: files ---------------------------------------------------
    vrows, unknown = [], []
    for sha, h in hashes.items():
        v = vt_files.get(sha)
        paths = sorted(p for p in h["paths"] if p)
        path = paths[0] if paths else "?"
        if v is None:
            continue
        link = f"https://www.virustotal.com/gui/file/{sha}"
        if not v.get("found"):
            vrows.append([path, sha, "not in VT", 0, "", "", ", ".join(sorted(h["sources"])),
                          link, ["unknown"]])
            if not h["packaged"]:
                unknown.append(path)
            continue
        mal, sus, tot = v["malicious"], v["suspicious"], v["total"]
        flags = ["malicious"] if mal else ["suspicious"] if sus else []
        vrows.append([path, sha, f"{mal}/{tot}", mal, v.get("label") or "",
                      fmt_ts(v.get("first_seen")), ", ".join(sorted(h["sources"])), link, flags])
        if mal or sus:
            # one lone engine is frequently a false positive; 5+ almost never is
            sev = ("critical" if mal >= 5 else "high" if mal >= 2 else
                   "medium" if mal == 1 else "low")
            add_finding(res, sev, "vt-file",
                        f"VirusTotal: {mal}/{tot} engines flag {path}"
                        + (f" ({v['label']})" if v.get("label") else ""),
                        "Antivirus engines on VirusTotal classify this exact file (by SHA-256) "
                        "as malicious. One or two detections can be false positives; five or "
                        "more almost never are.",
                        "Open the VirusTotal link for behaviour, relations and family; "
                        "contain the process and hunt the hash across the fleet.",
                        {"file": path, "all_paths": paths, "sha256": sha,
                         "detections": f"{mal} malicious, {sus} suspicious of {tot}",
                         "label": v.get("label"), "names": v.get("names"),
                         "type": v.get("type"), "first_seen": fmt_ts(v.get("first_seen")),
                         "seen_as": sorted(h["sources"]), "virustotal": link}, sha)
    if unknown:
        add_finding(res, "low", "vt-unknown",
                    f"{len(unknown)} unpackaged executable(s) were never seen by VirusTotal",
                    "Hashes unknown to VirusTotal are custom builds: in-house tools - or "
                    "implants compiled for this target. Worth a look when the rest of the "
                    "case is suspicious. (Nothing was uploaded.)", "",
                    {"files": sorted(unknown)[:40]}, "unknown")
    if vrows:
        vrows.sort(key=lambda r: (-r[3], r[2] != "not in VT", r[0]))
        inv["intel_vt"] = {"title": "VirusTotal - executables", "cat": "intel",
                           "cols": ["file", "sha256", "detections", "malicious", "label",
                                    "first seen", "seen as", "virustotal", "flags"],
                           "rows": vrows, "key": [1], "note": "Hash lookups only - no file "
                           "was uploaded. 'not in VT' = VirusTotal has never seen the file."}

    # ---- VirusTotal: IPs + geolocation ----------------------------------------
    grows = []
    for ip in sorted(ips, key=lambda x: (-len(ips[x]), x)):
        g = geo.get(ip) or {}
        v = vt_ips.get(ip)
        flags = []
        if g.get("hosting"):
            flags.append("hosting")
        if g.get("proxy"):
            flags.append("proxy/vpn")
        det = ""
        if v is not None:
            det = f"{v['malicious']}/{v['total']}" if v.get("found") else "not in VT"
            mal = v.get("malicious", 0) if v else 0
            sus = v.get("suspicious", 0) if v else 0
            rep = (v or {}).get("reputation") or 0
            # Real VT data: 1.1.1.1, 8.8.8.8, 9.9.9.9 and big cloud APIs carry a lone
            # detection. Popular, well-reputed addresses with <=2 hits are noise.
            noise = mal <= 2 and rep >= 50
            if v is not None and v.get("found") and (mal or sus) and not noise:
                flags.append("vt-malicious" if mal else "vt-suspicious")
                live = bool({"connection", "collector connection", "login"} & ips[ip])
                sev = ("critical" if live and mal >= 5 else
                       "high" if mal >= 5 or (live and mal >= 2) else
                       "medium" if mal >= 2 else "low")
                what = (f"{mal}/{v['total']} engines flag" if mal else
                        f"{sus}/{v['total']} engines call suspicious")
                add_finding(res, sev, "vt-ip",
                            f"VirusTotal: {what} {ip} ({', '.join(sorted(ips[ip]))})",
                            "The host talked to (or was logged into from) an address that "
                            "security vendors list as malicious - C2, scanner, or a known "
                            "attacker host.",
                            "Block it at the perimeter, find the owning process in the "
                            "Network tab, and search other hosts' logs for it.",
                            {"ip": ip, "seen_as": sorted(ips[ip]),
                             "detections": f"{mal} malicious, {sus} suspicious of {v['total']}",
                             "community_reputation": rep,
                             "as_owner": v.get("as_owner"), "country": v.get("country"),
                             "geo": geo_str(g), "tags": v.get("tags"),
                             "virustotal": f"https://www.virustotal.com/gui/ip-address/{ip}"},
                            ip, ["T1071"])
        grows.append([ip, g.get("country") or "", g.get("city") or "", g.get("asn") or "",
                      g.get("org") or "", det, ", ".join(sorted(ips[ip])),
                      f"https://www.virustotal.com/gui/ip-address/{ip}", flags])
    if grows:
        inv["intel_geo"] = {"title": "Public IP addresses - geolocation and reputation",
                            "cat": "intel",
                            "cols": ["ip", "country", "city", "asn", "organisation", "VT",
                                     "seen as", "virustotal", "flags"],
                            "rows": grows, "key": [0], "note": ""}

    # ---- annotate existing tables -------------------------------------------------
    def ip_vt(ip):
        v = vt_ips.get(norm_ip(ip) or "")
        if v is None:
            return ""
        return f"{v['malicious']}/{v['total']}" if v.get("found") else "not in VT"

    def exe_vt(sha, pkg):
        v = vt_files.get(sha) if sha else None
        if v is None:
            if not (sha and vt_on):
                return ""
            if pkg:
                return "dpkg-verified"
            if hashes.get(sha, {}).get("packaged"):
                return "copy of a packaged binary"     # renamed/copied system binary
            return "not looked up"
        if not v.get("found"):
            return "not in VT"
        s = f"{v['malicious']}/{v['total']}"
        return s + (f" {v['label']}" if v.get("label") else "")

    vt_on = intel_meta.get("virustotal")
    for name in ("services", "services_nondefault", "cron", "cron_nondefault"):
        t = inv.get(name)
        if not t or "exec VT" in t["cols"] or _col(t, "exec sha256") is None:
            continue
        si, pi, fi = _col(t, "exec sha256"), _col(t, "exec package"), _col(t, "flags")
        t["cols"].append("exec VT")
        for r in t["rows"]:
            r.append(exe_vt(r[si], r[pi]))
            v = vt_files.get(r[si])
            if v and v.get("found") and v["malicious"] >= 2 and "vt-malicious" not in r[fi]:
                r[fi].append("vt-malicious")
    for name, ipcol in (("connections", "remote"), ("listeners", None),
                        ("logins", "from"), ("failed_logins", "source")):
        t = inv.get(name)
        if not t or "location" in t["cols"]:
            continue
        i = _col(t, ipcol) if ipcol else None
        si, pi, fi = _col(t, "sha256"), _col(t, "package"), _col(t, "flags")
        if i is not None:
            t["cols"] += ["location", "ip VT"]
        if si is not None:
            t["cols"].append("exe VT")
        for r in t["rows"]:
            hot = False
            if i is not None:
                n = norm_ip(r[i])
                r.append(geo_str(geo.get(n)) if n else ("private" if r[i] else ""))
                r.append(ip_vt(r[i]))
                v = vt_ips.get(n or "")
                hot |= bool(v and v.get("found") and v["malicious"] >= 2)
            if si is not None:
                r.append(exe_vt(r[si], r[pi] if pi is not None else ""))
                v = vt_files.get(r[si])
                hot |= bool(v and v.get("found") and v["malicious"] >= 2)
            if hot and fi is not None and "vt-malicious" not in r[fi]:
                r[fi].append("vt-malicious")
    t = inv.get("processes")
    if t and _col(t, "sha256") is not None and "virustotal" not in t["cols"]:
        si = _col(t, "sha256")
        t["cols"].append("virustotal")
        for r in t["rows"]:
            v = vt_files.get(r[si]) if r[si] else None
            r.append("" if v is None else "not in VT" if not v.get("found")
                     else f"{v['malicious']}/{v['total']}")
            if v and v.get("found") and v["malicious"] and "vt-malicious" not in r[10]:
                r[10].append("vt-malicious")
    cc = Counter()
    for ip in ips:
        g = geo.get(ip)
        if g and g.get("cc"):
            cc[(g["cc"], g.get("country") or g["cc"])] += 1
    intel_meta["countries"] = [{"cc": k[0], "country": k[1], "ips": n} for k, n in cc.most_common()]
    intel_meta["vt_files"] = {"looked_up": len(vt_files),
                              "malicious": sum(1 for v in vt_files.values()
                                               if (v.get("malicious") or 0) >= 2),
                              "unknown": sum(1 for v in vt_files.values() if not v.get("found"))}
    intel_meta["vt_ips"] = {"looked_up": len(vt_ips),
                            "malicious": sum(1 for v in vt_ips.values()
                                             if (v.get("malicious") or 0) >= 2)}
    intel_meta["public_ips"] = len(ips)
    intel_meta["hashes"] = len(hashes)
    res["intel"] = intel_meta
    recompute(res)


# --------------------------------------------------------------------------
def build_timeline(coll_dir, geo, vt_ips, title):
    data = viz.build(coll_dir)
    for d in data["dests"]:
        g = geo.get(d["ip"])
        s = geo_str(g)
        v = vt_ips.get(d["ip"])
        if v and v.get("found") and v["malicious"]:
            s = (s + " · " if s else "") + f"VT {v['malicious']}/{v['total']}"
        d["geo"] = s
    return viz.fill(viz.TEMPLATE, data, TITLE=title, VERSION=ps.VERSION)


def main():
    ap = argparse.ArgumentParser(
        description="Analyse a ProcSnap case on the analysis machine: threat-intel "
                    "enrichment (geolocation, VirusTotal) and HTML reports.",
        epilog="VirusTotal key: --vt-key or the VT_API_KEY environment variable. Free keys "
               "allow 4 lookups/minute and 500/day; raise --vt-rate for premium keys.")
    ap.add_argument("case", help="case .tar.gz from collect_case.sh, a case dir, or triage.json")
    ap.add_argument("-o", "--out", help="output directory (default: <case>-analysis)")
    ap.add_argument("--vt-key", default=os.environ.get("VT_API_KEY"),
                    help="VirusTotal API key (default: $VT_API_KEY)")
    ap.add_argument("--vt-rate", type=float, default=4, help="VT requests per minute (default 4)")
    ap.add_argument("--vt-max", type=int, default=480,
                    help="max VT requests this run (default 480, under the free 500/day)")
    ap.add_argument("--vt-all", action="store_true",
                    help="also look up package-owned binaries (dpkg already verifies those)")
    ap.add_argument("--vt-no-ips", action="store_true", help="skip VirusTotal IP lookups")
    ap.add_argument("--geo", choices=("ip-api", "ipinfo", "none"), default="ip-api",
                    help="geolocation provider (default ip-api.com: free, no key, "
                         "non-commercial terms; ipinfo: free token, commercial use OK)")
    ap.add_argument("--ipinfo-token", default=os.environ.get("IPINFO_TOKEN"))
    ap.add_argument("--offline", action="store_true", help="no network lookups at all")
    ap.add_argument("--no-cache", action="store_true", help="ignore and don't write the cache")
    ap.add_argument("--compare", metavar="OLD.json", help="earlier triage.json for the Changes tab")
    ap.add_argument("--baseline", metavar="DB.json",
                    help="baseline DB (procsnap.py mkbaseline) of known-good services/cron jobs")
    ap.add_argument("-q", "--quiet", action="store_true")
    a = ap.parse_args()
    ps.protect_console()

    base = os.path.basename(a.case.rstrip("/"))
    for ext in (".tar.gz", ".tgz", ".tar", ".json"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    out = a.out or os.path.join(os.path.dirname(os.path.abspath(a.case.rstrip("/"))),
                                base + "-analysis")
    os.makedirs(out, mode=0o700, exist_ok=True)
    work = os.path.join(out, "case")
    if os.path.isfile(a.case) and not a.case.endswith(".json"):
        if os.path.exists(work):
            shutil.rmtree(work)
        os.makedirs(work, mode=0o700)
    case_dir, tj, coll, meta = open_case(a.case, work)
    res = None
    if tj:
        try:
            with open(tj) as fh:
                res = json.load(fh)
        except (OSError, ValueError) as e:
            raise SystemExit(f"{tj}: unreadable or not valid JSON ({e})")
        if not isinstance(res, dict) or res.get("kind") != "triage":
            raise SystemExit(f"{tj} is not a procsnap triage.json")
        if a.baseline:
            with open(a.baseline) as fh:
                n = ps.apply_baseline(res, json.load(fh))
            say(f"[*] baseline: {n} difference(s) from {a.baseline}", a.quiet)
    say(f"[*] case: {case_dir}\n    triage: {tj or '-'}\n    collector: {coll or '-'}", a.quiet)

    ips, hashes = gather(res, coll)
    say(f"[*] {len(ips)} public IP(s), {len(hashes)} executable hash(es)", a.quiet)
    cache = Cache(not a.no_cache)
    notes = []
    geo, vt_files, vt_ips = {}, {}, {}
    if not a.offline and a.geo != "none" and ips:
        try:
            geo = geo_lookup(ips, a.geo, a.ipinfo_token, cache, a.quiet)
        except (HTTPError, urllib.error.URLError, OSError, ValueError, HTTPException) as e:
            notes.append(f"geolocation failed: {e}")
            say(f"[!] geolocation failed: {e}", a.quiet)
    if a.vt_key and not a.offline:
        vt = VT(a.vt_key, a.vt_rate, cache, a.quiet, a.vt_max)
        # most valuable first: unpackaged running binaries + evidence, then IPs with
        # live connections/logins, then the rest
        files = sorted(hashes, key=lambda s: (hashes[s]["packaged"], not hashes[s]["net"],
                                              not hashes[s]["persist"], not hashes[s]["running"]))
        if not a.vt_all:
            files = [s for s in files if not hashes[s]["packaged"]]
        iplist = [] if a.vt_no_ips else sorted(
            ips, key=lambda i: (not ({"connection", "login", "collector connection"} & ips[i]), i))
        queue = [("file", s) for s in files] + [("ip", i) for i in iplist]
        n_net = sum(1 for k, x in queue if (cache.get("vt_file", x) if k == "file"
                                                else cache.get("vt_ip", x)) is None)
        say(f"[vt] {len(files)} file hash(es) + {len(iplist)} IP(s); {n_net} need the API"
            + (f" (~{int(n_net * 60 / a.vt_rate // 60)} min at {a.vt_rate:g}/min)"
               if n_net > a.vt_rate else ""), a.quiet)
        try:
            for i, (kind, x) in enumerate(queue, 1):
                if kind == "file":
                    vt_files[x] = vt.file(x)
                else:
                    vt_ips[x] = vt.ip(x)
                if not a.quiet and i % 5 == 0:
                    say(f"[vt] {i}/{len(queue)}", a.quiet)
        except VTStop as e:
            notes.append(str(e))
            say(f"[!] {e} - continuing with {len(vt_files) + len(vt_ips)} result(s)", a.quiet)
        finally:
            cache.save()                              # never lose answers already paid for
    elif not a.offline:
        notes.append("VirusTotal not queried (no --vt-key / VT_API_KEY)")
    cache.save()

    intel_meta = {"generated": time.time(), "geo_provider": None if a.offline else a.geo,
                  "virustotal": bool(a.vt_key) and not a.offline, "notes": notes,
                  "case_meta": meta}
    written = []
    if res is not None:
        enrich(res, ips, hashes, geo, vt_files, vt_ips, intel_meta)
        for n in notes:
            res["errors"].append({"check": "threat intel", "error": n})
        with open(os.path.join(out, "triage.enriched.json"), "w") as fh:
            json.dump(res, fh, indent=1, default=str)
        b = None
        if a.compare:
            with open(a.compare) as fh:
                b = json.load(fh)
        page = viz.render_triage(res, b)
        with open(os.path.join(out, "triage.html"), "w") as fh:
            fh.write(page)
        written += ["triage.html", "triage.enriched.json"]
    if coll:
        host = (res or {}).get("host", {}).get("hostname") or meta.get("host") or "?"
        with open(os.path.join(out, "timeline.html"), "w") as fh:
            fh.write(build_timeline(coll, geo, vt_ips, f"Timeline · {host}"))
        written.append("timeline.html")
    with open(os.path.join(out, "intel.json"), "w") as fh:
        json.dump({"geo": geo, "virustotal_files": vt_files, "virustotal_ips": vt_ips,
                   "notes": notes}, fh, indent=1)
    written.append("intel.json")

    if res is not None:
        ps.print_triage(res, 25, sys.stdout)
    im = (res or {}).get("intel", {})
    if im:
        top = ", ".join(f"{c['cc']} {c['ips']}" for c in im.get("countries", [])[:8])
        print(f"intel: {im.get('public_ips', 0)} public IPs ({top or 'no geo'}); "
              f"VT files {im['vt_files']['looked_up']} looked up, "
              f"{im['vt_files']['malicious']} flagged (2+ engines); VT IPs {im['vt_ips']['looked_up']}, "
              f"{im['vt_ips']['malicious']} flagged (2+ engines)")
    t = (res or {}).get("inventory", {}).get("connections")
    if t and "location" in t["cols"]:
        c = t["cols"].index
        ext = [r for r in t["rows"] if public_ip(r[c("remote")])]
        if ext:
            print(f"\nexternal connections ({len(ext)}):")
            for r in ext[:20]:
                print(f"  {str(r[c('direction')] or '?'):<8} {r[c('process')]}({r[c('pid')]}) user={r[c('user')]}"
                      f" -> {r[c('remote')]}:{r[c('rport')]}  [{r[c('location')] or '?'}]"
                      f"  ipVT={r[c('ip VT')] or '-'}  exeVT={r[c('exe VT')] or '-'}")
    for n in notes:
        print(f"note : {n}")
    print(f"\nreports in {out}/: " + ", ".join(written))


if __name__ == "__main__":
    main()
