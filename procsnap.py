#!/usr/bin/env python3
"""
procsnap - periodic process + network snapshotter for Linux hosts.

Reads /proc directly (no ps/netstat/ss dependency), records a delta event
stream to JSONL so long runs stay small, and ships with an analysis side.

  Collect:
    sudo ./procsnap.py collect --interval 10 --out /var/log/procsnap
    sudo ./procsnap.py collect --interval 5 --stdout          # live to terminal

  Analyse:
    ./procsnap.py report   /var/log/procsnap
    ./procsnap.py timeline /var/log/procsnap --since 2h
    ./procsnap.py procs    /var/log/procsnap --grep curl
    ./procsnap.py conns    /var/log/procsnap --remote 1.2.3.4
    ./procsnap.py sqlite   /var/log/procsnap -o snap.db

  Service:
    sudo ./procsnap.py install-service --interval 10
"""
from __future__ import annotations

import argparse
import array
import base64
import difflib
import fcntl
import glob
import gzip
import hashlib
import json
import os
import pwd
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import stat
import struct
import sys
import time
import zlib
from collections import Counter, defaultdict
from datetime import datetime

VERSION = "2.0.0"
HZ = os.sysconf("SC_CLK_TCK")
PAGE_KB = os.sysconf("SC_PAGE_SIZE") // 1024

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}

SUSPECT_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/", "/home/")
# Command-line patterns that are rarely legitimate. Shared by the collector,
# the triage engine (cron, systemd, shell init, history) and the HTML report.
SUSPECT_CMD = re.compile(
    r"(curl|wget)\b[^|;]*\|\s*(ba|da|z)?sh\b|base64\s+(-d|--decode)|/dev/(tcp|udp)/|"
    r"\bnc(at)?\b[^|;]*\s-[a-z]*e\s|\bmkfifo\b[^;]*\bnc\b|socat\b[^;]*\bexec:|"
    r"\b(ba)?sh\s+-i\s*[<>]&|chmod\s+(\+x|[0-7]?7[0-7][0-7])\s+/(tmp|dev/shm|var/tmp)/|"
    r"openssl\s+s_client\b[^;]*-connect|xmrig|kinsing|kdevtmpfsi|stratum\+tcp|"
    r"\bhistory\s+-c\b|unset\s+HISTFILE|HISTFILE=/dev/null|chattr\s+\+i\s",
    re.I,
)
# Inline interpreter one-liners: common in admin tooling, so context only.
SUSPECT_INLINE = re.compile(r"\b(python[0-9.]*\s+-c|perl\s+-e|php\s+-r|ruby\s+-e)\s", re.I)

_UID_CACHE: dict[int, str] = {}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def uname(uid: int) -> str:
    if uid not in _UID_CACHE:
        try:
            _UID_CACHE[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _UID_CACHE[uid] = str(uid)
    return _UID_CACHE[uid]


def boot_time() -> float:
    try:
        with open("/proc/stat") as fh:
            for line in fh:
                if line.startswith("btime"):
                    return float(line.split()[1])
    except OSError:
        pass
    with open("/proc/uptime") as fh:
        return time.time() - float(fh.read().split()[0])


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def readlink(path: str) -> str | None:
    try:
        return os.readlink(path)
    except OSError:
        return None


def exe_sha256(pid: int, cache: dict, cap: int = 512 << 20, cached_only: bool = False) -> str | None:
    """SHA-256 of a process's executable, read through /proc/<pid>/exe.

    Works for deleted and memfd binaries too. Cached per (device, inode, size,
    mtime) so each distinct binary is hashed once, however many processes run it.
    """
    path = f"/proc/{pid}/exe"
    try:
        st = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
        return None
    key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
    if key not in cache and cached_only:
        return None
    if key not in cache:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for b in iter(lambda: fh.read(1 << 20), b""):
                    h.update(b)
            cache[key] = h.hexdigest()
        except OSError:
            cache[key] = None
    return cache[key]


def hex_ip(h: str) -> str:
    """/proc/net/* stores addresses as little-endian hex words."""
    try:
        if len(h) == 8:
            return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(h, 16)))
        if len(h) == 32:
            raw = b"".join(struct.pack("<I", int(h[i:i + 8], 16)) for i in range(0, 32, 8))
            ip = socket.inet_ntop(socket.AF_INET6, raw)
            return ip[7:] if ip.startswith("::ffff:") else ip
    except (ValueError, OSError):
        pass
    return h


def is_private(ip) -> bool:
    ip = str(ip or "")
    if ip.startswith(("10.", "127.", "192.168.", "169.254.", "::1", "fe80:", "fc", "fd")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (ValueError, IndexError):
            return False
    return ip in ("0.0.0.0", "::", "")


def duration(spec: str) -> float:
    """Accept 10, 10s, 5m, 1h, 90ms-style intervals -> seconds (float)."""
    spec = str(spec).strip().lower()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?", spec)
    if not m:
        raise argparse.ArgumentTypeError(
            f"bad duration {spec!r} - use e.g. 10, 30s, 10m, 1h")
    val = float(m.group(1))
    mult = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2) or "s"]
    secs = val * mult
    if secs < 0.05:
        raise argparse.ArgumentTypeError(f"interval {spec!r} is too small (min 50ms)")
    return secs


def human_dur(secs: float) -> str:
    if secs >= 3600 and secs % 3600 == 0:
        return f"{int(secs // 3600)}h"
    if secs >= 60 and secs % 60 == 0:
        return f"{int(secs // 60)}m"
    return f"{secs:g}s"


def human_span(secs) -> str:
    """3725 -> '1h 02m', 93784 -> '1d 2h 03m'"""
    if secs is None:
        return ""
    secs = max(0, int(secs))
    d, r = divmod(secs, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return f"{d}d {h}h {m:02d}m"
    if h:
        return f"{h}h {m:02d}m"
    return f"{m}m {s:02d}s"


def parse_since(spec: str) -> float:
    m = re.fullmatch(r"(\d+)\s*([smhd])", spec.strip(), re.I)
    if m:
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2).lower()]
        return time.time() - int(m.group(1)) * mult
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(spec, fmt).timestamp()
        except ValueError:
            continue
    raise SystemExit(f"cannot parse --since {spec!r} (use 30m / 2h / 7d / 'YYYY-MM-DD HH:MM')")


# --------------------------------------------------------------------------
# collection
# --------------------------------------------------------------------------
def scan_procs(bt: float, want_fds: bool = True):
    """Return (procs_by_key, socket_inode -> pid)."""
    procs: dict[tuple[int, int], dict] = {}
    inode2pid: dict[str, int] = {}

    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        base = "/proc/" + entry.name
        try:
            with open(base + "/stat", "rb") as fh:
                raw = fh.read().decode("utf-8", "replace")
            uid = os.stat(base).st_uid
        except OSError:
            continue

        close = raw.rfind(")")
        if close < 0:
            continue
        comm = raw[raw.find("(") + 1:close]
        f = raw[close + 2:].split()
        if len(f) < 22:
            continue

        try:
            ppid = int(f[1])
            sid = int(f[3])
            tty_nr = int(f[4])
            cpu_ticks = int(f[11]) + int(f[12])
            nthreads = int(f[17])
            starttime = int(f[19])
            rss_kb = int(f[21]) * PAGE_KB
        except (ValueError, IndexError):
            continue

        try:
            with open(base + "/cmdline", "rb") as fh:
                cmdline = fh.read().decode("utf-8", "replace").replace("\0", " ").strip()
        except OSError:
            cmdline = ""

        kthread = not cmdline
        exe = readlink(base + "/exe")
        deleted = bool(exe and exe.endswith(" (deleted)"))
        if deleted:
            exe = exe[: -len(" (deleted)")]

        cg = ""
        try:
            with open(base + "/cgroup") as fh:
                cg = fh.readline().strip().rsplit("/", 1)[-1][:64]
        except OSError:
            pass

        rec = {
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "user": uname(uid),
            "comm": comm,
            "cmdline": cmdline or f"[{comm}]",
            "exe": exe,
            "exe_deleted": deleted,
            "cwd": readlink(base + "/cwd"),
            "sid": sid,
            "tty": tty_nr,
            "nthreads": nthreads,
            "rss_kb": rss_kb,
            "cpu_s": round(cpu_ticks / HZ, 2),
            "cgroup": cg,
            "kthread": kthread,
            "start": round(bt + starttime / HZ, 2),
        }
        procs[(pid, starttime)] = rec

        if want_fds and not kthread:
            try:
                with os.scandir(base + "/fd") as it:
                    for fd in it:
                        tgt = readlink(fd.path)
                        if tgt and tgt.startswith("socket:["):
                            inode2pid[tgt[8:-1]] = pid
            except OSError:
                pass

    return procs, inode2pid


def scan_sockets(inode2pid, procs_by_pid, include_timewait=False):
    """Return (listen_dict, conn_dict) keyed for delta comparison."""
    listen: dict[tuple, dict] = {}
    conns: dict[tuple, dict] = {}

    sources = (
        ("tcp", "/proc/net/tcp"), ("tcp", "/proc/net/tcp6"),
        ("udp", "/proc/net/udp"), ("udp", "/proc/net/udp6"),
    )
    for proto, path in sources:
        try:
            with open(path) as fh:
                lines = fh.read().splitlines()[1:]
        except OSError:
            continue

        for line in lines:
            f = line.split()
            if len(f) < 10:
                continue
            try:
                lip_h, lport_h = f[1].split(":")
                rip_h, rport_h = f[2].split(":")
                lport, rport = int(lport_h, 16), int(rport_h, 16)
            except ValueError:
                continue

            if proto == "tcp":
                state = TCP_STATES.get(f[3].upper(), f[3])
            else:
                state = "BOUND" if rport == 0 else "ACTIVE"
            if state == "TIME_WAIT" and not include_timewait:
                continue

            inode = f[9]
            pid = inode2pid.get(inode)
            p = procs_by_pid.get(pid, {})
            lip, rip = hex_ip(lip_h), hex_ip(rip_h)

            base = {
                "proto": proto,
                "laddr": lip, "lport": lport,
                "state": state,
                "pid": pid,
                "comm": p.get("comm"),
                "cmdline": p.get("cmdline"),
                "exe": p.get("exe"),
                "user": p.get("user") or uname(int(f[7])),
            }
            if rport == 0 or state == "LISTEN":
                listen[(proto, lip, lport)] = base
            else:
                base["raddr"], base["rport"] = rip, rport
                conns[(proto, lip, lport, rip, rport)] = base

    return listen, conns


class Writer:
    """Day-rotating JSONL writer (optionally gzipped)."""

    def __init__(self, outdir=None, gz=False, to_stdout=False, retain_days=0):
        self.outdir = outdir
        self.gz = gz
        self.to_stdout = to_stdout
        self.retain_days = retain_days
        self.day = None
        self.fh = None
        if outdir:
            os.makedirs(outdir, exist_ok=True)

    def _roll(self):
        day = time.strftime("%Y%m%d")
        if day == self.day and self.fh:
            return
        if self.fh:
            self.fh.close()
        self.day = day
        ext = ".jsonl.gz" if self.gz else ".jsonl"
        path = os.path.join(self.outdir, f"procsnap-{day}{ext}")
        self.fh = gzip.open(path, "at") if self.gz else open(path, "a", buffering=1)
        self._prune()

    def _prune(self):
        if not self.retain_days:
            return
        cutoff = time.time() - self.retain_days * 86400
        for p in glob.glob(os.path.join(self.outdir, "procsnap-*.jsonl*")):
            try:
                if os.path.getmtime(p) < cutoff:
                    os.remove(p)
            except OSError:
                pass

    def emit(self, ev: dict):
        line = json.dumps(ev, separators=(",", ":"), default=str)
        if self.to_stdout:
            print(line, flush=True)
        if self.outdir:
            self._roll()
            self.fh.write(line + "\n")

    def close(self):
        if self.fh:
            self.fh.close()


def cmd_collect(a):
    if os.geteuid() != 0:
        print("[!] not root - cmdline/exe/socket-to-PID will be missing for other users' "
              "processes", file=sys.stderr)

    bt = boot_time()
    w = Writer(None if a.stdout and not a.out else a.out, a.gzip, a.stdout, a.retain_days)

    running = True

    def stop(_sig, _frm):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    if not a.stdout:
        where = a.out or "stdout"
        stop_hint = f"stops after {a.count} snapshots" if a.count else "runs until Ctrl+C / kill"
        print(f"[procsnap] every {human_dur(a.interval)} -> {where}  ({stop_hint}, pid {os.getpid()})",
              file=sys.stderr)

    w.emit({
        "ts": round(time.time(), 3), "ev": "collector_start", "version": VERSION,
        "host": socket.gethostname(), "kernel": os.uname().release,
        "boot": round(bt, 2), "interval": a.interval,
        "interval_h": human_dur(a.interval), "root": os.geteuid() == 0,
        "net": not a.no_net,
    })

    prev_procs: dict = {}
    prev_listen: dict = {}
    prev_conns: dict = {}
    first_seen: dict = {}
    peak_rss: dict = {}
    hcache: dict = {}
    hqueue: list = []
    n = 0

    while running:
        t0 = time.time()
        procs, inode2pid = scan_procs(bt, want_fds=not a.no_net)
        if a.no_kthreads:
            procs = {k: v for k, v in procs.items() if not v["kthread"]}
        by_pid = {v["pid"]: v for v in procs.values()}

        if a.no_net:
            listen, conns = {}, {}
        else:
            listen, conns = scan_sockets(inode2pid, by_pid, a.include_timewait)
            if a.no_loopback:
                conns = {k: v for k, v in conns.items()
                         if not (v["laddr"].startswith("127.") or v["laddr"] in ("::1",))}

        ts = round(time.time(), 3)

        # --- process deltas -------------------------------------------------
        for key, rec in procs.items():
            peak_rss[key] = max(peak_rss.get(key, 0), rec["rss_kb"])
            if key not in prev_procs:
                first_seen[key] = ts
                ev = dict(rec)
                ev.update(ts=ts, ev="proc_start", baseline=(n == 0))
                if not a.no_hash and not rec["kthread"]:
                    # never hash inside the snapshot: a cold cache (first snapshot, big
                    # binaries) took ~16 s and left the collector blind. Known binaries
                    # are tagged now; the rest are hashed in the idle time below and
                    # reported as an exe_hash event.
                    known = exe_sha256(rec["pid"], hcache, cached_only=True)
                    if known:
                        ev["sha256"] = known
                    else:
                        hqueue.append((rec["pid"], rec["start"], rec["comm"], rec["exe"]))
                par = by_pid.get(rec["ppid"])
                if par:
                    ev["pcomm"] = par["comm"]
                    ev["pcmdline"] = par["cmdline"]
                w.emit(ev)

            elif rec["exe_deleted"] and not prev_procs[key]["exe_deleted"]:
                # binary removed while running: the classic "delete myself after
                # start" move. Without this event a process first seen before the
                # deletion would never be flagged.
                w.emit({"ts": ts, "ev": "exe_deleted", "pid": rec["pid"], "ppid": rec["ppid"],
                        "user": rec["user"], "comm": rec["comm"], "cmdline": rec["cmdline"],
                        "exe": rec["exe"], "exe_deleted": True, "start": rec["start"]})

        for key, rec in prev_procs.items():
            if key not in procs:
                w.emit({
                    "ts": ts, "ev": "proc_exit", "pid": rec["pid"], "ppid": rec["ppid"],
                    "user": rec["user"], "comm": rec["comm"], "cmdline": rec["cmdline"],
                    "exe": rec["exe"], "start": rec["start"],
                    "lifetime_s": round(ts - rec["start"], 2),
                    "cpu_s": rec["cpu_s"], "rss_kb_peak": peak_rss.pop(key, rec["rss_kb"]),
                })
                first_seen.pop(key, None)

        # --- socket deltas --------------------------------------------------
        for key, rec in listen.items():
            if key not in prev_listen:
                first_seen[("L",) + key] = ts
                w.emit({**rec, "ts": ts, "ev": "listen_open", "baseline": n == 0})
        for key, rec in prev_listen.items():
            if key not in listen:
                st = first_seen.pop(("L",) + key, None)
                w.emit({**rec, "ts": ts, "ev": "listen_close",
                        "duration_s": round(ts - st, 1) if st else None})

        lports = {(k[0], k[2]) for k in listen}
        for key, rec in conns.items():
            if key not in prev_conns:
                first_seen[("C",) + key] = ts
                w.emit({**rec, "ts": ts, "ev": "conn_open", "baseline": n == 0,
                        "dir": "inbound" if (rec["proto"], rec["lport"]) in lports
                        else "outbound"})
        for key, rec in prev_conns.items():
            if key not in conns:
                st = first_seen.pop(("C",) + key, None)
                w.emit({**rec, "ts": ts, "ev": "conn_close",
                        "duration_s": round(ts - st, 1) if st else None})

        # --- periodic full inventory (resync point) -------------------------
        if a.full_every and n % a.full_every == 0:
            w.emit({
                "ts": ts, "ev": "inventory",
                "procs": sorted(procs.values(), key=lambda r: r["pid"]),
                "listen": list(listen.values()),
                "conns": list(conns.values()),
            })

        w.emit({
            "ts": ts, "ev": "heartbeat", "n": n,
            "nproc": len(procs), "nlisten": len(listen), "nconn": len(conns),
            "scan_ms": round((time.time() - t0) * 1000, 1),
        })

        prev_procs, prev_listen, prev_conns = procs, listen, conns
        n += 1

        if a.count and n >= a.count:
            break
        deadline = t0 + a.interval
        while running and time.time() < deadline:
            if hqueue and deadline - time.time() > 0.05:
                pid, start, comm, exe = hqueue.pop(0)          # idle-time hashing
                sha = exe_sha256(pid, hcache)
                if sha:
                    w.emit({"ts": round(time.time(), 3), "ev": "exe_hash", "pid": pid,
                            "start": start, "comm": comm, "exe": exe, "sha256": sha})
                continue
            time.sleep(min(0.25, max(0.0, deadline - time.time())))

    w.emit({"ts": round(time.time(), 3), "ev": "collector_stop", "snapshots": n})
    w.close()


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------
def load(path, since=None, until=None):
    files = []
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "procsnap-*.jsonl*")))
    elif os.path.isfile(path):
        files = [path]
    if not files:
        raise SystemExit(f"no procsnap logs found at {path}")
    for fp in files:
        opener = gzip.open if fp.endswith(".gz") else open
        try:
            with opener(fp, "rt", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(ev, dict):          # crafted/corrupt line
                        continue
                    ts = ev.get("ts", 0)
                    if not isinstance(ts, (int, float)):
                        continue
                    if since and ts < since:
                        continue
                    if until and ts > until:
                        continue
                    yield ev
        except (EOFError, zlib.error, gzip.BadGzipFile) as e:
            # a .gz still being written (or cut by kill -9) ends mid-member:
            # keep everything read so far instead of crashing the analysis.
            print(f"[!] {fp}: truncated ({e.__class__.__name__}) - using the part before the cut",
                  file=sys.stderr)


# Severity tiers. HIGH = act on it. LOW = context only, expect benign hits.
SEVERITY = {
    "exe-deleted": "high",
    "exe-in-world-writable": "high",
    "suspicious-cmdline": "high",
    "comm-exe-mismatch": "low",
    "listen-all-ifaces-highport": "low",
    "inline-interpreter": "low",
}

_SCRIPT_EXT = (".sh", ".py", ".pl", ".rb", ".php", ".js", ".bash")
# comm values the kernel or a multi-call binary legitimately reports under a
# different exe name.
_COMM_ALIAS = {
    "sh": {"dash", "bash", "busybox"},
    "systemd-udevd": {"udevadm"},
    "systemd": {"systemd-executor"},
}


def _strip_ver(name: str) -> str:
    """python3.12 -> python, ruby2.7 -> ruby"""
    return re.sub(r"[-_.0-9]+$", "", name)


def comm_exe_mismatch(comm: str | None, exe: str | None) -> bool:
    """True only when comm and exe genuinely disagree.

    The naive basename(exe) != comm test is ~90% false positives: interpreters
    carry version suffixes, scripts report their own filename, the kernel
    truncates comm at 15 chars, and multi-call binaries are exec'd under
    an alias.
    """
    if not comm or not exe:
        return False
    if comm.startswith("("):                      # (sd-pam) and friends
        return False
    if len(comm) >= 15:                           # kernel-truncated, can't compare
        return False
    if comm.endswith(_SCRIPT_EXT):                # script name as comm
        return False
    base = os.path.basename(exe)
    if not base or not re.search(r"[A-Za-z]", base):   # versioned filename, e.g. 2.1.241
        return False
    if base.startswith(comm) or comm.startswith(base): # truncation / version suffix
        return False
    if _strip_ver(base) == _strip_ver(comm):
        return False
    if base in _COMM_ALIAS.get(comm, ()):
        return False
    return True


def suspicious(ev) -> list[str]:
    tags = []
    exe = ev.get("exe") or ""
    cmd = ev.get("cmdline") or ""
    if exe.startswith(SUSPECT_DIRS):
        tags.append("exe-in-world-writable")
    if ev.get("exe_deleted"):
        tags.append("exe-deleted")
    if SUSPECT_CMD.search(cmd):
        tags.append("suspicious-cmdline")
    elif SUSPECT_INLINE.search(cmd + " "):
        tags.append("inline-interpreter")
    if comm_exe_mismatch(ev.get("comm"), exe):
        tags.append("comm-exe-mismatch")
    if ev.get("ev") == "listen_open" and ev.get("laddr") in ("0.0.0.0", "::") \
            and (ev.get("lport") or 0) > 1024:
        tags.append("listen-all-ifaces-highport")
    return tags


# --------------------------------------------------------------------------
# point-in-time state reconstruction  (snapshot browsing + diffing)
# --------------------------------------------------------------------------
def snapshot_points(path, since=None):
    """Every heartbeat is one snapshot. Returns [(n, ts)] in order."""
    pts = []
    for ev in load(path, since):
        if ev.get("ev") == "heartbeat":
            pts.append((len(pts) + 1, ev["ts"]))
    return pts


def resolve_at(pts, spec):
    """'#3' -> 3rd snapshot; 'first'/'last'; a clock time; or an epoch/ISO time."""
    if not pts:
        raise SystemExit("no snapshots in this log")
    spec = str(spec).strip()
    if spec in ("first", "0"):
        return pts[0]
    if spec == "last":
        return pts[-1]
    if spec.startswith("#"):
        i = int(spec[1:])
        if not 1 <= i <= len(pts):
            raise SystemExit(f"snapshot {spec} out of range (1..{len(pts)})")
        return pts[i - 1]
    if re.fullmatch(r"\d{1,2}:\d{2}(:\d{2})?", spec):
        day = datetime.fromtimestamp(pts[0][1]).strftime("%Y-%m-%d")
        fmt = "%Y-%m-%d %H:%M:%S" if spec.count(":") == 2 else "%Y-%m-%d %H:%M"
        want = datetime.strptime(f"{day} {spec}", fmt).timestamp()
    else:
        try:
            want = float(spec)
        except ValueError:
            want = parse_since(spec)
    # nearest snapshot at or before the requested time
    best = pts[0]
    for n, ts in pts:
        if ts <= want + 0.001:
            best = (n, ts)
        else:
            break
    return best


def reconstruct(path, at):
    """Replay the delta stream up to `at` and return the exact state then."""
    procs, listen, conns = {}, {}, {}
    for ev in load(path):
        ts = ev.get("ts", 0)
        if ts > at + 0.001:
            break
        k = ev.get("ev")
        if k == "collector_start":
            # a new collector session restarts the delta chain from a fresh
            # baseline: anything carried over from the previous session is stale.
            # This is what makes cron-driven `once` logs reconstruct correctly,
            # and what stops a reboot from leaving dead processes "alive".
            procs.clear(); listen.clear(); conns.clear()
        elif k == "proc_start":
            procs[(ev.get("pid"), ev.get("start"))] = ev
        elif k == "proc_exit":
            procs.pop((ev.get("pid"), ev.get("start")), None)
        elif k == "exe_deleted":
            p = procs.get((ev.get("pid"), ev.get("start")))
            if p:
                procs[(ev.get("pid"), ev.get("start"))] = dict(p, exe_deleted=True)
        elif k == "listen_open":
            listen[(ev.get("proto"), ev.get("laddr"), ev.get("lport"))] = ev
        elif k == "listen_close":
            listen.pop((ev.get("proto"), ev.get("laddr"), ev.get("lport")), None)
        elif k == "conn_open":
            conns[(ev.get("proto"), ev.get("laddr"), ev.get("lport"),
                   ev.get("raddr"), ev.get("rport"))] = ev
        elif k == "conn_close":
            conns.pop((ev.get("proto"), ev.get("laddr"), ev.get("lport"),
                       ev.get("raddr"), ev.get("rport")), None)
    return procs, listen, conns


def _proc_line(ev, by_pid):
    pid = f"{ev.get('pid'):>7} " if by_pid else ""
    return f"{pid}{ev.get('user','?'):<12} {ev.get('cmdline','?')}"


def _listen_line(ev, by_pid):
    pid = f"{ev.get('pid') or '-':>7} " if by_pid else ""
    return (f"{pid}{ev.get('proto','?'):<5} "
            f"{str(ev.get('laddr'))+':'+str(ev.get('lport')):<26} "
            f"{ev.get('comm') or '?'}")


def _conn_line(ev, by_pid):
    pid = f"{ev.get('pid') or '-':>7} " if by_pid else ""
    return (f"{pid}{ev.get('proto','?'):<5} "
            f"{str(ev.get('laddr'))+':'+str(ev.get('lport')):<24}-> "
            f"{str(ev.get('raddr'))+':'+str(ev.get('rport')):<24} "
            f"{ev.get('state','') :<12} {ev.get('comm') or '?'}")


SECTIONS = (("PROCESSES", 0, _proc_line),
            ("LISTENERS", 1, _listen_line),
            ("CONNECTIONS", 2, _conn_line))


def state_lines(state, by_pid, no_kthreads=False):
    """dict section -> {line: event}"""
    out = {}
    for name, idx, fmt in SECTIONS:
        d = {}
        for ev in state[idx].values():
            if no_kthreads and ev.get("kthread"):
                continue
            d[fmt(ev, by_pid)] = ev
        out[name] = d
    return out


def cmd_snapshots(a):
    pts = snapshot_points(a.path, parse_since(a.since) if a.since else None)
    print(f"{len(pts)} snapshots in {a.path}")
    step = max(1, len(pts) // a.limit) if a.limit and len(pts) > a.limit else 1
    for n, ts in pts[::step]:
        print(f"  #{n:<6} {iso(ts)}   {ts}")
    if step > 1:
        print(f"  (showing 1 in {step} - raise --limit, or --limit 0, for all)")


def cmd_show(a):
    pts = snapshot_points(a.path)
    n, ts = resolve_at(pts, a.at)
    state = reconstruct(a.path, ts)
    lines = state_lines(state, a.pid, a.no_kthreads)
    print(f"\033[1msnapshot #{n}\033[0m  {iso(ts)}   ({a.path})")
    for name, _, _ in SECTIONS:
        d = lines[name]
        print(f"\n\033[1m{name}\033[0m ({len(d)})\n" + "-" * (len(name) + 8))
        for line in sorted(d):
            print("  " + line)


def cmd_diff(a):
    pts = snapshot_points(a.path)
    picks = [resolve_at(pts, x) for x in a.at]
    if len(picks) < 2:
        raise SystemExit("need at least two --at values to diff")
    states = [state_lines(reconstruct(a.path, ts), a.pid, a.no_kthreads)
              for _, ts in picks]

    print(f"\033[1mcomparing {len(picks)} snapshots\033[0m  ({a.path})")
    for i, (n, ts) in enumerate(picks):
        print(f"  S{i+1} = snapshot #{n}  {iso(ts)}")

    changed = 0
    for name, _, _ in SECTIONS:
        sets = [set(st[name]) for st in states]
        union = set().union(*sets)
        common = set.intersection(*sets)
        diffs = sorted(union - common)
        print(f"\n\033[1m{name}\033[0m  "
              f"{len(common)} identical, \033[33m{len(diffs)} differing\033[0m\n"
              + "-" * (len(name) + 30))
        if not diffs:
            print("  (no change)")
            continue
        changed += len(diffs)

        if len(picks) == 2:
            for line in diffs:
                sign = "\033[32m+\033[0m" if line in sets[1] else "\033[31m-\033[0m"
                print(f"  {sign} {line}")
                if a.verbose:
                    ev = states[1][name].get(line) or states[0][name].get(line)
                    if ev and ev.get("exe"):
                        print(f"      exe={ev['exe']}"
                              + ("  \033[31m[DELETED]\033[0m"
                                 if ev.get("exe_deleted") else ""))
        else:
            hdr = "".join(f" S{i+1}" for i in range(len(picks)))
            print(f"  {hdr}   entity")
            for line in diffs:
                mark = "".join("  X" if line in s else "  ." for s in sets)
                print(f"  {mark}   {line}")

    print(f"\n{changed} differing line(s) across "
          f"{len(SECTIONS)} sections.\n")


def cmd_report(a):
    since = parse_since(a.since) if a.since else None
    starts = exits = 0
    hb = None
    hosts, sessions = set(), 0
    proc_agg = Counter()
    user_agg = Counter()
    parent_agg = Counter()
    listeners = {}
    remotes = Counter()
    rports = Counter()
    ext_conns = Counter()
    flags = defaultdict(list)
    t_min = t_max = None

    for ev in load(a.path, since):
        ts = ev.get("ts", 0)
        t_min = ts if t_min is None else min(t_min, ts)
        t_max = ts if t_max is None else max(t_max, ts)
        k = ev.get("ev")

        if k == "collector_start":
            hosts.add(ev.get("host", "?"))
            sessions += 1
        elif k == "heartbeat":
            hb = ev
        elif k == "proc_start":
            starts += 1
            proc_agg[ev.get("cmdline", "?")[:160]] += 1
            user_agg[ev.get("user", "?")] += 1
            if ev.get("pcomm"):
                parent_agg[f"{ev['pcomm']} -> {ev.get('comm')}"] += 1
            for t in suspicious(ev):
                flags[t].append(ev)
        elif k == "proc_exit":
            exits += 1
        elif k == "exe_deleted":
            for t in suspicious(ev):
                flags[t].append(ev)
        elif k == "listen_open":
            listeners[(ev["proto"], ev["laddr"], ev["lport"])] = ev
            for t in suspicious(ev):
                flags[t].append(ev)
        elif k == "conn_open":
            r = ev.get("raddr", "")
            remotes[r] += 1
            rports[f"{ev.get('proto')}/{ev.get('rport')}"] += 1
            if not is_private(r):
                ext_conns[(ev.get("comm") or "?", r, ev.get("rport"))] += 1

    def hdr(t):
        print(f"\n\033[1m{t}\033[0m\n" + "-" * len(t))

    print(f"\033[1mprocsnap report\033[0m  ({a.path})")
    if t_min:
        span = t_max - t_min
        print(f"  window   : {iso(t_min)} -> {iso(t_max)}  ({span/3600:.1f}h)")
    print(f"  hosts    : {', '.join(sorted(hosts)) or '?'}   collector sessions: {sessions}")
    print(f"  processes: {starts} started / {exits} exited")
    if hb:
        print(f"  last hb  : {hb['nproc']} procs, {hb['nlisten']} listeners, "
              f"{hb['nconn']} conns, scan {hb['scan_ms']}ms")

    hdr(f"Top {a.top} command lines")
    for cmd, c in proc_agg.most_common(a.top):
        print(f"  {c:6d}  {cmd}")

    hdr("Executions by user")
    for u, c in user_agg.most_common(15):
        print(f"  {c:6d}  {u}")

    if parent_agg:
        hdr(f"Top {a.top} parent -> child pairs")
        for pair, c in parent_agg.most_common(a.top):
            print(f"  {c:6d}  {pair}")

    hdr("Listening sockets seen")
    for (proto, ip, port), ev in sorted(listeners.items(), key=lambda x: x[0][2]):
        who = ev.get("comm") or "?"
        print(f"  {proto:4s} {ip + ':' + str(port):<24s} {who:<20s} "
              f"pid={ev.get('pid')} user={ev.get('user')}")

    hdr(f"Top {a.top} remote peers")
    for ip, c in remotes.most_common(a.top):
        mark = "" if is_private(ip) else "  [external]"
        print(f"  {c:6d}  {ip}{mark}")

    hdr("Top remote ports")
    for p, c in rports.most_common(15):
        print(f"  {c:6d}  {p}")

    if ext_conns:
        hdr(f"External destinations by process (top {a.top})")
        for (comm, ip, port), c in ext_conns.most_common(a.top):
            print(f"  {c:6d}  {comm:<20s} -> {ip}:{port}")

    for level, colour, label in (("high", "31", "Heuristic flags - HIGH (act on these)"),
                                 ("low", "33", "Heuristic flags - LOW (context, expect benign hits)")):
        tags = {t: e for t, e in flags.items() if SEVERITY.get(t, "low") == level}
        hdr(label)
        if not tags:
            print("  none")
            continue
        for tag, evs in sorted(tags.items(), key=lambda x: -len(x[1])):
            print(f"  \033[{colour}m{tag}\033[0m ({len(evs)})")
            seen = set()
            for ev in evs:
                sig = ev.get("cmdline") or f"{ev.get('laddr')}:{ev.get('lport')}"
                if sig in seen:
                    continue
                seen.add(sig)
                print(f"      {iso(ev['ts'])} pid={ev.get('pid')} {sig[:130]}")
                if len(seen) >= 8:
                    print("      ...")
                    break
    print()


def cmd_timeline(a):
    since = parse_since(a.since) if a.since else None
    pat = re.compile(a.grep, re.I) if a.grep else None
    kinds = set(a.ev.split(",")) if a.ev else None
    shown = 0
    for ev in load(a.path, since):
        k = ev.get("ev")
        if k in ("heartbeat", "inventory", "exe_hash") and not (kinds and k in kinds):
            continue
        if kinds and k not in kinds:
            continue
        if ev.get("baseline") and not a.baseline:
            continue
        blob = json.dumps(ev, default=str)
        if pat and not pat.search(blob):
            continue

        if k == "proc_start":
            body = (f"pid={ev.get('pid'):<7} ppid={ev.get('ppid'):<7} "
                    f"{ev.get('user','?'):<10} {ev.get('cmdline','')[:110]}")
        elif k == "exe_deleted":
            body = f"pid={ev.get('pid'):<7} binary removed while running: {ev.get('exe')}"
        elif k == "proc_exit":
            body = (f"pid={ev.get('pid'):<7} lifetime={ev.get('lifetime_s')}s "
                    f"cpu={ev.get('cpu_s')}s {ev.get('cmdline','')[:90]}")
        elif k in ("listen_open", "listen_close"):
            body = (f"{ev.get('proto')} {ev.get('laddr')}:{ev.get('lport')} "
                    f"pid={ev.get('pid')} {ev.get('comm') or ''}")
        elif k in ("conn_open", "conn_close"):
            body = (f"{ev.get('proto')} {ev.get('laddr')}:{ev.get('lport')} -> "
                    f"{ev.get('raddr')}:{ev.get('rport')} {ev.get('state','')} "
                    f"pid={ev.get('pid')} {ev.get('comm') or ''}")
        else:
            body = json.dumps({x: y for x, y in ev.items() if x not in ("ts", "ev")},
                              default=str)[:140]

        tags = suspicious(ev)
        if tags:
            hi = [t for t in tags if SEVERITY.get(t, "low") == "high"]
            colour = "31" if hi else "33"
            suffix = f"  \033[{colour}m[{','.join(tags)}]\033[0m"
        else:
            suffix = ""
        print(f"{iso(ev['ts'])}  {k:<13} {body}{suffix}")
        shown += 1
        if a.limit and shown >= a.limit:
            print(f"... truncated at --limit {a.limit}")
            break


def cmd_procs(a):
    since = parse_since(a.since) if a.since else None
    pat = re.compile(a.grep, re.I) if a.grep else None
    agg = {}
    for ev in load(a.path, since):
        if ev.get("ev") != "proc_start":
            continue
        cmd = ev.get("cmdline", "?")
        if pat and not pat.search(cmd) and not pat.search(ev.get("comm") or ""):
            continue
        e = agg.setdefault(cmd, {"n": 0, "first": ev["ts"], "last": ev["ts"],
                                 "users": Counter(), "exe": ev.get("exe"),
                                 "parents": Counter()})
        e["n"] += 1
        e["first"] = min(e["first"], ev["ts"])
        e["last"] = max(e["last"], ev["ts"])
        e["users"][ev.get("user", "?")] += 1
        if ev.get("pcomm"):
            e["parents"][ev["pcomm"]] += 1

    for cmd, e in sorted(agg.items(), key=lambda x: -x[1]["n"])[: a.top]:
        print(f"\033[1m{e['n']:>6}x\033[0m {cmd[:150]}")
        print(f"        exe={e['exe']}  users={dict(e['users'])} "
              f"parents={dict(e['parents'].most_common(3))}")
        print(f"        first={iso(e['first'])}  last={iso(e['last'])}")


def cmd_conns(a):
    since = parse_since(a.since) if a.since else None
    agg = {}
    for ev in load(a.path, since):
        if ev.get("ev") != "conn_open":
            continue
        r = ev.get("raddr", "")
        if a.remote and a.remote not in r:
            continue
        if a.port and ev.get("rport") != a.port:
            continue
        if a.external_only and is_private(r):
            continue
        key = (ev.get("comm") or "?", ev.get("proto"), r, ev.get("rport"))
        e = agg.setdefault(key, {"n": 0, "first": ev["ts"], "last": ev["ts"],
                                 "pids": set(), "cmd": ev.get("cmdline")})
        e["n"] += 1
        e["first"] = min(e["first"], ev["ts"])
        e["last"] = max(e["last"], ev["ts"])
        if ev.get("pid"):
            e["pids"].add(ev["pid"])

    for (comm, proto, ip, port), e in sorted(agg.items(), key=lambda x: -x[1]["n"])[: a.top]:
        ext = "" if is_private(ip) else " [external]"
        print(f"\033[1m{e['n']:>6}x\033[0m {comm:<18} {proto} -> {ip}:{port}{ext}")
        print(f"        pids={sorted(e['pids'])[:10]}  {iso(e['first'])} .. {iso(e['last'])}")
        if a.verbose and e["cmd"]:
            print(f"        {e['cmd'][:150]}")


def cmd_sqlite(a):
    if os.path.exists(a.out) and not a.force:
        raise SystemExit(f"{a.out} exists (use --force to overwrite)")
    if os.path.exists(a.out):
        os.remove(a.out)
    db = sqlite3.connect(a.out)
    db.executescript("""
        CREATE TABLE procs(ts REAL, ev TEXT, pid INT, ppid INT, user TEXT, comm TEXT,
            cmdline TEXT, exe TEXT, exe_deleted INT, cwd TEXT, cgroup TEXT, start REAL,
            lifetime_s REAL, cpu_s REAL, rss_kb INT, pcomm TEXT, baseline INT);
        CREATE TABLE socks(ts REAL, ev TEXT, proto TEXT, laddr TEXT, lport INT,
            raddr TEXT, rport INT, state TEXT, pid INT, comm TEXT, cmdline TEXT,
            user TEXT, duration_s REAL, baseline INT);
        CREATE TABLE heartbeat(ts REAL, nproc INT, nlisten INT, nconn INT, scan_ms REAL);
        CREATE INDEX i_p_ts ON procs(ts); CREATE INDEX i_p_cmd ON procs(comm);
        CREATE INDEX i_s_ts ON socks(ts); CREATE INDEX i_s_r  ON socks(raddr);
    """)
    np_ = ns = nh = 0
    for ev in load(a.path):
        k = ev.get("ev")
        if k in ("proc_start", "proc_exit", "exe_deleted"):
            db.execute("INSERT INTO procs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                ev.get("ts"), k, ev.get("pid"), ev.get("ppid"), ev.get("user"),
                ev.get("comm"), ev.get("cmdline"), ev.get("exe"),
                int(bool(ev.get("exe_deleted"))), ev.get("cwd"), ev.get("cgroup"),
                ev.get("start"), ev.get("lifetime_s"), ev.get("cpu_s"),
                ev.get("rss_kb") or ev.get("rss_kb_peak"), ev.get("pcomm"),
                int(bool(ev.get("baseline")))))
            np_ += 1
        elif k in ("listen_open", "listen_close", "conn_open", "conn_close"):
            db.execute("INSERT INTO socks VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                ev.get("ts"), k, ev.get("proto"), ev.get("laddr"), ev.get("lport"),
                ev.get("raddr"), ev.get("rport"), ev.get("state"), ev.get("pid"),
                ev.get("comm"), ev.get("cmdline"), ev.get("user"),
                ev.get("duration_s"), int(bool(ev.get("baseline")))))
            ns += 1
        elif k == "heartbeat":
            db.execute("INSERT INTO heartbeat VALUES(?,?,?,?,?)", (
                ev.get("ts"), ev.get("nproc"), ev.get("nlisten"),
                ev.get("nconn"), ev.get("scan_ms")))
            nh += 1
    db.commit()
    db.close()
    print(f"wrote {a.out}: {np_} process rows, {ns} socket rows, {nh} heartbeats")
    print(f'try: sqlite3 {a.out} "SELECT comm,raddr,rport,COUNT(*) FROM socks '
          'WHERE ev=\'conn_open\' GROUP BY 1,2,3 ORDER BY 4 DESC LIMIT 20;"')


def cmd_once(a):
    """Single point-in-time snapshot, then exit."""
    a.count = 1
    a.full_every = 1
    a.retain_days = 0
    a.gzip = False
    cmd_collect(a)
    if a.out:
        day = time.strftime("%Y%m%d")
        path = os.path.join(a.out, f"procsnap-{day}.jsonl")
        print(f"snapshot written to {path}", file=sys.stderr)


def cmd_install_service(a):
    script = os.path.abspath(__file__)
    # land a full inventory roughly hourly, whatever the interval
    full_every = max(1, int(round(3600 / max(a.interval, 1))))
    unit = f"""[Unit]
Description=procsnap - process & network snapshotter
After=network.target

[Service]
Type=simple
ExecStart="{sys.executable}" "{script}" collect --interval {human_dur(a.interval)} --out "{a.out}" --gzip --retain-days {a.retain_days} --full-every {full_every}
Restart=always
RestartSec=5
Nice=10
IOSchedulingClass=idle

[Install]
WantedBy=multi-user.target
"""
    try:                 # the unit runs this file as root at every boot
        sst = os.stat(script)
        if sst.st_uid != 0 or sst.st_mode & 0o022 or os.stat(os.path.dirname(script)).st_mode & 0o002:
            print(f"[!] {script} is not root-owned or is group/world-writable: anyone who can "
                  "edit it gets root via this service. Copy it to /usr/local/sbin (root:root, "
                  "0755) and run install-service from there.", file=sys.stderr)
    except OSError:
        pass
    path = "/etc/systemd/system/procsnap.service"
    if a.print_only or os.geteuid() != 0:
        print(unit)
        print(f"# write the above to {path}, then:", file=sys.stderr)
    else:
        with open(path, "w") as fh:
            fh.write(unit)
        print(f"wrote {path}")
    print("systemctl daemon-reload && systemctl enable --now procsnap", file=sys.stderr)


# ==========================================================================
# TRIAGE - one-shot compromise assessment of a live host or a mounted image
# ==========================================================================
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

TACTICS = ("Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
           "Credential Access", "Lateral Movement", "Command and Control", "Impact")
MITRE = {
    "T1014": ("Rootkit", "Defense Evasion"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1036.004": ("Masquerade Task or Service", "Defense Evasion"),
    "T1036.005": ("Match Legitimate Name or Location", "Defense Evasion"),
    "T1037.004": ("RC Scripts", "Persistence"),
    "T1040": ("Network Sniffing", "Credential Access"),
    "T1053.002": ("Scheduled Task: At", "Persistence"),
    "T1053.003": ("Scheduled Task: Cron", "Persistence"),
    "T1053.006": ("Scheduled Task: Systemd Timers", "Persistence"),
    "T1055.008": ("Ptrace System Calls", "Defense Evasion"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1070.002": ("Clear Linux or Mac System Logs", "Defense Evasion"),
    "T1070.003": ("Clear Command History", "Defense Evasion"),
    "T1070.004": ("File Deletion", "Defense Evasion"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1078.003": ("Valid Accounts: Local Accounts", "Privilege Escalation"),
    "T1098.004": ("SSH Authorized Keys", "Persistence"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1205.002": ("Traffic Signaling: Socket Filters", "Command and Control"),
    "T1496": ("Resource Hijacking", "Impact"),
    "T1505.003": ("Web Shell", "Persistence"),
    "T1543.002": ("Systemd Service", "Persistence"),
    "T1546": ("Event Triggered Execution", "Persistence"),
    "T1546.004": ("Unix Shell Configuration Modification", "Persistence"),
    "T1546.017": ("Udev Rules", "Persistence"),
    "T1547.006": ("Kernel Modules and Extensions", "Persistence"),
    "T1547.013": ("XDG Autostart Entries", "Persistence"),
    "T1548.001": ("Setuid and Setgid", "Privilege Escalation"),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation"),
    "T1554": ("Compromise Host Software Binary", "Persistence"),
    "T1556.003": ("Pluggable Authentication Modules", "Credential Access"),
    "T1564.001": ("Hidden Files and Directories", "Defense Evasion"),
    "T1574.006": ("Dynamic Linker Hijacking", "Persistence"),
    "T1620": ("Reflective Code Loading", "Defense Evasion"),
    "T1037": ("Boot or Logon Initialization Scripts", "Persistence"),
    "T1222.002": ("Linux File and Directory Permissions Modification", "Defense Evasion"),
    "T1505": ("Server Software Component", "Persistence"),
    "T1543.005": ("Container Service", "Persistence"),
    "T1546.018": ("Python Startup Hooks", "Persistence"),
    "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation"),
    "T1556": ("Modify Authentication Process", "Credential Access"),
    "T1574.007": ("Path Interception by PATH Environment Variable", "Persistence"),
    "T1611": ("Escape to Host", "Privilege Escalation"),
}

WW_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")
WW_PATH = re.compile(r"(?<![\w.~-])(?:/tmp|/var/tmp|/dev/shm|/run/shm)/[^\s'\";|&)]+")
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ksh93", "mksh", "csh", "tcsh", "fish",
          "ash", "busybox"}
NET_TOOLS = {"nc", "ncat", "netcat", "nc.traditional", "nc.openbsd", "socat", "telnet",
             "openssl", "cryptcat"}
INTERP = re.compile(r"^(python[0-9.]*|perl[0-9.]*|php[0-9.]*|ruby[0-9.]*|node|lua[0-9.]*)$")
SERVICE_PARENT = re.compile(
    r"^(apache2|httpd|nginx|php-fpm.*|php-cgi.*|lsphp.*|lighttpd|caddy|tomcat.*|java|"
    r"uwsgi|mysqld|mariadbd|postgres|redis-server|mongod|named|exim4|vsftpd|proftpd|"
    r"pure-ftpd)$")
SERVICE_USERS = {"www-data", "apache", "nginx", "nobody", "mysql", "postgres", "redis",
                 "tomcat", "jenkins", "bind", "Debian-exim", "ftp"}
KTHREAD_NAME = re.compile(r"^\[?(kworker|ksoftirqd|kthreadd|migration|rcu_|watchdog/|"
                          r"kswapd|jbd2|kblockd|irq/|kdevtmpfs|khugepaged|kauditd)")
MINER_RE = re.compile(r"xmrig|xmr-stak|minerd|cpuminer|kdevtmpfsi|kinsing|stratum\+tcp|"
                      r"nicehash|cryptonight|c3pool|supportxmr|moneroocean|nanopool", re.I)
ROOTKIT_RE = re.compile(r"diamorphine|reptile|suterusu|khook|adore|knark|kovid|jynx|azazel|"
                        r"beurk|bdvl|vlany|puszek|nuk3gh0st|enyelkm|kbeast|brokepkg|caraxes|"
                        r"kingkit|ebpfkit|boopkit|triplecross|symbiote|bpfdoor|pumakit|"
                        r"kitsune|hideproc", re.I)
WEBSHELL_RE = re.compile(
    rb"(?:eval|assert|system|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(\s*@?"
    rb"(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|\$_(?:GET|POST|REQUEST|"
    rb"COOKIE|SERVER)\b)|preg_replace\s*\(\s*['\"][^'\"]{0,80}/e[a-z]*['\"]|"
    rb"create_function\s*\([^)]{0,120}\$_(?:GET|POST|REQUEST)|c99shell|r57shell|b374k|"
    rb"FilesMan|IndoXploit|Runtime\.getRuntime\(\)\.exec\(\s*request\.getParameter", re.I)
WEB_EXT = (".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phar", ".inc",
           ".jsp", ".jspx", ".aspx", ".cgi", ".pl")
NOLOGIN = ("nologin", "false", "/sync", "/halt", "/shutdown")
CAP_NAMES = ("chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap "
             "linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock "
             "ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin "
             "sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write "
             "audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend "
             "audit_read perfmon bpf checkpoint_restore").split()
DANGER_CAPS = {"setuid", "setgid", "dac_override", "dac_read_search", "sys_admin",
               "sys_ptrace", "sys_module", "chown", "fowner", "setfcap", "bpf"}
TAINT = {0: ("P", "proprietary module", "info"), 1: ("F", "module force-loaded", "high"),
         12: ("O", "out-of-tree module", "low"), 13: ("E", "unsigned module", "medium"),
         4: ("M", "machine check", "info"), 9: ("W", "kernel warning", "info"),
         14: ("L", "soft lockup", "info"), 15: ("K", "live-patched", "info")}
# dpkg-verified by default: binaries, PAM, sshd helpers and the libraries real
# Linux implants have trojaned (Ebury: libkeyutils; others: libpam, libc, libaudit).
DPKG_CRITICAL = re.compile(
    r"^(usr/)?s?bin/|^(usr/)?lib(64)?/[^/]+/security/|^(usr/)?lib(64)?/security/|"
    r"^usr/lib/openssh/|^usr/libexec/|^(usr/)?lib(64)?/(x86_64|aarch64|i386|arm)[^/]*/"
    r"lib(keyutils|pam|pam_misc|audit|selinux|c|crypt|systemd|ssl|crypto|z|curl|nss_files|"
    r"resolv|dl|pthread|util)[.-][^/]*so")
UT = struct.Struct("hi32s4s32s256shhiii4i20s")     # glibc struct utmp (x86_64/aarch64)


def _sha256(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def _md5(path, chunk=1 << 20):
    try:                                    # FIPS hosts refuse plain md5()
        h = hashlib.md5(usedforsecurity=False)
    except TypeError:                       # Python 3.8 has no usedforsecurity
        h = hashlib.md5()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def decode_caps(raw: bytes) -> list[str]:
    """security.capability xattr -> ['cap_setuid', ...] (permitted set)."""
    if len(raw) < 12:
        return []
    bits = struct.unpack_from("<I", raw, 4)[0]
    if len(raw) >= 20:
        bits |= struct.unpack_from("<I", raw, 12)[0] << 32
    return ["cap_" + (CAP_NAMES[i] if i < len(CAP_NAMES) else str(i))
            for i in range(64) if bits >> i & 1]


def ssh_fingerprint(b64: str) -> str:
    try:
        d = hashlib.sha256(base64.b64decode(b64)).digest()
        return "SHA256:" + base64.b64encode(d).decode().rstrip("=")
    except (ValueError, TypeError):
        return "?"


class Triage:
    """Runs every check, collects findings + inventories + evidence.

    root='/' means live host: process, network and kernel checks run too.
    Any other root is treated as a mounted image (dead-box triage): only
    file-based checks run, and every path is resolved under that root.
    """

    def __init__(self, a):
        self.root = os.path.abspath(a.root or "/")
        self.live = self.root == "/"
        self.days = a.days
        self.deep = a.deep
        self.out = a.out
        self.collect = not a.no_collect
        self.ev_cap = a.evidence_mb * 1024 * 1024
        self.budget = a.walk_budget
        self.quiet = a.quiet
        self.now = time.time()
        self.recent = self.now - self.days * 86400
        self.findings, self.inv, self.errors, self.timings = [], {}, [], {}
        self.evidence, self._ev_seen, self._fids = [], {}, set()
        self._owned = None
        self._diverted = set()
        self.users = []
        self.procs = {}
        self.inode_pids = defaultdict(set)
        self.pflags = defaultdict(list)
        self.selfpid = os.getpid()
        self.hostinfo = {}
        self.hcache = {}
        self._md5 = None
        self._finfo = {}
        self.unit_recs = []
        self.enabled_units = set()

    # ---------------------------------------------------------------- paths
    def p(self, path):
        return path if self.live else os.path.join(self.root, path.lstrip("/"))

    def hostpath(self, fspath):
        return fspath if self.live else "/" + os.path.relpath(fspath, self.root)

    def read(self, path, limit=8 << 20):
        # chunked: one huge read() on /proc/sys files fails with ENOMEM
        try:
            buf = []
            n = 0
            with open(self.p(path), "rb") as fh:
                while n < limit:
                    b = fh.read(min(65536, limit - n))
                    if not b:
                        break
                    buf.append(b)
                    n += len(b)
            return b"".join(buf).decode("utf-8", "replace")
        except OSError:
            return None

    def ls(self, path):
        try:
            return sorted(os.listdir(self.p(path)))
        except OSError:
            return []

    def lstat(self, path):
        try:
            return os.lstat(self.p(path))
        except OSError:
            return None

    def is_recent(self, st):
        return bool(st) and max(st.st_ctime, st.st_mtime) >= self.recent

    # ------------------------------------------------------ dpkg ownership
    _MERGED = ("bin", "sbin", "lib", "lib32", "lib64", "libx32")

    def _variants(self, path):
        out = [path]
        parts = path.split("/")
        if len(parts) > 2:
            if parts[1] in self._MERGED:
                out.append("/usr" + path)
            elif parts[1] == "usr" and parts[2] in self._MERGED:
                out.append(path[4:])
        return out

    def owned(self):
        if self._owned is None:
            self._owned = {}
            for lf in glob.glob(os.path.join(self.p("/var/lib/dpkg/info"), "*.list")):
                pkg = os.path.basename(lf)[:-5].split(":")[0]
                try:
                    with open(lf, errors="replace") as fh:
                        for line in fh:
                            self._owned[line.rstrip("\n")] = pkg
                except OSError:
                    pass
            div = (self.read("/var/lib/dpkg/diversions") or "").splitlines()
            for i in range(0, len(div) - 2, 3):
                self._diverted.update((div[i], div[i + 1]))
        return self._owned

    def owner(self, path):
        d = self.owned()
        if not d:
            return None
        for v in self._variants(path):
            if v in d:
                return d[v]
        try:
            real = os.path.realpath(self.p(path))
            if not self.live:
                if not real.startswith(self.root):
                    return None
                real = self.hostpath(real)
            if real != path:
                for v in self._variants(real):
                    if v in d:
                        return d[v]
        except OSError:
            pass
        return None

    # ------------------------------------------------------------ recording
    def add(self, sev, cat, check, title, mitre=(), why="", fix="", ev=None, key=None):
        fid = hashlib.sha1(f"{check}|{title if key is None else key}".encode()).hexdigest()[:12]
        if fid in self._fids:
            return None
        self._fids.add(fid)
        f = {"id": fid, "sev": sev, "cat": cat, "check": check, "title": title,
             "mitre": [mitre] if isinstance(mitre, str) else list(mitre),
             "why": why, "fix": fix, "evidence": ev or {}}
        self.findings.append(f)
        return f

    def grab(self, path, name=None, why=""):
        """Hash a file and (optionally) copy it into <case>/evidence/. -> sha256"""
        src = path if path.startswith("/proc/") else self.p(path)
        if src in self._ev_seen:
            return self._ev_seen[src]
        try:
            st = os.stat(src)
            if not stat.S_ISREG(st.st_mode):
                return None
        except OSError:
            return None
        rec = {"path": path, "size": st.st_size, "why": why, "sha256": None, "saved": None}
        try:
            rec["sha256"] = _sha256(src)
        except OSError as e:
            rec["error"] = str(e)
        if self.collect and self.out and rec["sha256"] and st.st_size <= self.ev_cap:
            d = os.path.join(self.out, "evidence")
            os.makedirs(d, mode=0o700, exist_ok=True)
            base = re.sub(r"[^\w.-]", "_", name or os.path.basename(path) or "file")[:60]
            fn = f"{rec['sha256'][:16]}_{base}.sample"
            dst = os.path.join(d, fn)
            try:
                if not os.path.exists(dst):
                    shutil.copyfile(src, dst)
                    os.chmod(dst, 0o400)
                rec["saved"] = "evidence/" + fn
            except OSError as e:
                rec["error"] = str(e)
        elif rec["sha256"] and st.st_size > self.ev_cap:
            rec["error"] = f"not copied: larger than --evidence-mb {self.ev_cap >> 20}"
        self.evidence.append(rec)
        self._ev_seen[src] = rec["sha256"]
        return rec["sha256"]

    def table(self, name, title, cat, cols, rows, key=None, note=""):
        self.inv[name] = {"title": title, "cat": cat, "cols": cols, "rows": rows,
                          "key": key if key is not None else list(range(len(cols))),
                          "note": note}

    def log(self, msg):
        if not self.quiet:
            print(f"\033[2m[*] {msg}\033[0m" if sys.stderr.isatty() else f"[*] {msg}",
                  file=sys.stderr)

    # ------------------------------------------------------------------ run
    def run(self):
        checks = [("host", self.c_host)]
        if self.live:
            checks += [("processes", self.c_processes), ("hidden pids", self.c_hidden_pids),
                       ("network", self.c_network), ("kernel", self.c_kernel)]
        checks += [("accounts", self.c_accounts), ("ssh", self.c_ssh), ("sudo", self.c_sudo),
                   ("pam", self.c_pam), ("dynamic linker", self.c_preload),
                   ("cron / at", self.c_cron), ("systemd", self.c_systemd),
                   ("other autostarts", self.c_autostart),
                   ("more persistence", self.c_more_persistence),
                   ("containers", self.c_containers), ("immutable files", self.c_immutable),
                   ("shell init", self.c_shell_init),
                   ("shell history", self.c_history), ("logins", self.c_logins),
                   ("sessions", self.c_sessions),
                   ("log integrity", self.c_logs), ("package integrity", self.c_packages),
                   ("filesystem sweep", self.c_filesystem)]
        t_start = time.time()
        for name, fn in checks:
            t = time.time()
            self.log(name)
            try:
                fn()
            except Exception as e:      # one broken check must never kill the triage
                self.errors.append({"check": name, "error": f"{type(e).__name__}: {e}"})
            self.timings[name] = round(time.time() - t, 2)
        self.findings.sort(key=lambda f: (SEV_RANK[f["sev"]], f["cat"], f["title"]))
        self.duration = round(time.time() - t_start, 1)

    # =============================================================== checks
    def c_host(self):
        osr = {}
        for line in (self.read("/etc/os-release") or "").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                osr[k] = v.strip().strip('"')
        h = self.hostinfo
        h["hostname"] = ((self.read("/etc/hostname") or "").strip() or "?")
        h["os"] = osr.get("PRETTY_NAME", "?")
        h["os_family"] = " ".join(x for x in (osr.get("ID"), osr.get("ID_LIKE")) if x)
        h["mode"] = "live" if self.live else f"offline image at {self.root}"
        h["root_privileges"] = os.geteuid() == 0
        h["dpkg_packages"] = len(glob.glob(self.p("/var/lib/dpkg/info") + "/*.list"))
        if self.live:
            u = os.uname()
            h["hostname"] = socket.gethostname()
            h["kernel"], h["arch"] = u.release, u.machine
            bt = boot_time()
            h["boot"], h["uptime_s"] = round(bt), round(time.time() - bt)
            h["tainted"] = int((self.read("/proc/sys/kernel/tainted") or "0").strip() or 0)
            h["timezone"] = time.strftime("%Z %z")
            ips = []
            try:
                ips = sorted({ai[4][0] for ai in socket.getaddrinfo(socket.gethostname(), None)})
            except OSError:
                pass
            h["addresses"] = ips
        if self.live:
            cg = (self.read("/proc/1/cgroup") or "") + (self.read("/proc/1/environ") or "")
            m = re.search(r"(docker|kubepods|containerd|libpod|lxc|podman)", cg)
            if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv") or m:
                h["container"] = m.group(1) if m else "yes"
                self.errors.append({"check": "host", "error":
                                    f"running inside a container ({h['container']}): process, "
                                    "network and kernel views are the container's; triage the "
                                    "host itself for kernel-level results"})
        if not h["dpkg_packages"]:
            self.errors.append({"check": "host", "error":
                                "no dpkg database - package-ownership and integrity checks "
                                "are disabled (not a Debian/Ubuntu system?)"})
        if self.live and os.geteuid() != 0:
            self.errors.append({"check": "host", "error":
                                "not running as root - other users' processes, sockets, "
                                "/etc/shadow and many files are unreadable; results are partial"})

    # ------------------------------------------------------------- process
    def _ticks(self):
        out = {}
        for e in os.scandir("/proc"):
            if e.name.isdigit():
                try:
                    with open(f"/proc/{e.name}/stat", "rb") as fh:
                        raw = fh.read().decode("utf-8", "replace")
                    f = raw[raw.rfind(")") + 2:].split()
                    out[int(e.name)] = (int(f[11]) + int(f[12]), int(f[19]))
                except (OSError, ValueError, IndexError):
                    pass
        return out

    def _pflag(self, pid, tag):
        if tag not in self.pflags[pid]:
            self.pflags[pid].append(tag)

    def _pev(self, r):
        par = self.procs.get(r["ppid"], {})
        return {"pid": r["pid"], "user": r["user"], "exe": r["exe"], "cmdline": r["cmdline"],
                "cwd": r.get("cwd"), "parent": f"{par.get('comm', '?')} ({r['ppid']})",
                "parent_cmdline": par.get("cmdline"), "started": iso(r["start"])}

    def _ancestors(self, pid, depth=8):
        out, seen = [], set()
        while pid in self.procs and pid not in seen and len(out) < depth:
            seen.add(pid)
            pid = self.procs[pid]["ppid"]
            if pid in self.procs:
                out.append(self.procs[pid])
        return out

    def _inet_inodes(self):
        out = set()
        for p_ in ("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"):
            for line in (self.read(p_) or "").splitlines()[1:]:
                f = line.split()
                if len(f) > 9:
                    out.add(f[9])
        return out

    def c_processes(self):
        t1 = self._ticks()
        time.sleep(1.0)
        procs, _ = scan_procs(boot_time(), want_fds=False)
        t2 = self._ticks()
        for (pid, st), rec in procs.items():
            if pid == self.selfpid:
                continue
            r = dict(rec)
            r["cpu_pct"] = (round((t2[pid][0] - t1[pid][0]) / HZ * 100, 1)
                            if pid in t1 and pid in t2 and t1[pid][1] == t2[pid][1] else None)
            base = f"/proc/{pid}"
            r["fd012"], r["bpf"], r["preload"], r["tracer"] = {}, 0, None, 0
            if not r["kthread"]:
                try:
                    with os.scandir(base + "/fd") as it:
                        for fd in it:
                            tgt = readlink(fd.path)
                            if not tgt:
                                continue
                            if tgt.startswith("socket:["):
                                self.inode_pids[tgt[8:-1]].add(pid)
                            elif tgt == "anon_inode:bpf-prog":
                                r["bpf"] += 1
                            if fd.name in ("0", "1", "2"):
                                r["fd012"][fd.name] = tgt
                except OSError:
                    pass
                try:
                    with open(base + "/environ", "rb") as fh:
                        for kv in fh.read().split(b"\0"):
                            if kv.startswith(b"LD_PRELOAD="):
                                r["preload"] = kv[11:].decode("utf-8", "replace").strip()
                except OSError:
                    pass
                st_txt = self.read(base + "/status") or ""
                m = re.search(r"^TracerPid:\s*(\d+)", st_txt, re.M)
                r["tracer"] = int(m.group(1)) if m else 0
                try:
                    with open(base + "/cmdline", "rb") as fh:
                        r["argv0"] = fh.read().split(b"\0")[0].decode("utf-8", "replace")
                except OSError:
                    r["argv0"] = ""
            self.procs[pid] = r

        inet = self._inet_inodes()
        try:
            mysid = os.getsid(0)
        except OSError:
            mysid = None
        # the analyst's own session (this tool, the shell it runs in, pipes) is
        # not evidence: skip it so it doesn't pollute the findings
        self.analyst = {pid for pid, r in self.procs.items() if mysid and r.get("sid") == mysid}
        unpackaged = {}
        for pid, r in self.procs.items():
            if r["kthread"]:
                continue
            if pid in self.analyst:
                self._pflag(pid, "analyst-session")
                continue
            exe, cmd, comm = r["exe"] or "", r["cmdline"] or "", r["comm"] or ""
            ev = self._pev(r)
            key = f"{exe}|{cmd}"
            if exe.startswith("/memfd:"):
                sha = self.grab(f"/proc/{pid}/exe", f"memfd-{pid}", "fileless process")
                self.add("critical", "process", "memfd-exe",
                         f"Fileless process {comm} ({pid}) runs from memory ({exe})",
                         ["T1620"], "The executable lives only in an anonymous memfd. "
                         "Legitimate software almost never does this; loaders and implants do.",
                         "Dump /proc/<pid>/exe and memory before killing it.",
                         dict(ev, sha256=sha), key)
                self._pflag(pid, "memfd")
            elif r["exe_deleted"]:
                pk = self.owner(exe) if os.path.exists(exe) else None
                sha = self.grab(f"/proc/{pid}/exe", f"deleted-{comm}-{pid}", "deleted exe")
                if pk:
                    self.add("low", "process", "exe-replaced",
                             f"{comm} ({pid}) runs an old copy of {exe} (package {pk})",
                             [], "The binary was replaced on disk while running - normally a "
                             "package upgrade without a service restart.",
                             "Restart the service; compare the dumped hash with the package.",
                             dict(ev, sha256=sha), key)
                else:
                    self.add("high", "process", "exe-deleted",
                             f"{comm} ({pid}) runs from a deleted file {exe}",
                             ["T1070.004"], "Malware commonly deletes its binary after start "
                             "to hinder recovery. /proc/<pid>/exe is now the only copy.",
                             "The binary was copied to evidence/ from /proc/<pid>/exe.",
                             dict(ev, sha256=sha), key)
                    self._pflag(pid, "deleted-exe")
            if exe.startswith(WW_DIRS):
                sha = self.grab(f"/proc/{pid}/exe", f"{comm}-{pid}", "exe in world-writable dir")
                self.add("high", "process", "exe-world-writable",
                         f"{comm} ({pid}) runs from world-writable {os.path.dirname(exe)}",
                         ["T1105"], "Dropped payloads land in /tmp, /var/tmp and /dev/shm "
                         "because any user can write there.", "", dict(ev, sha256=sha), key)
                self._pflag(pid, "ww-exe")
            if (r.get("argv0", "").startswith("[") or KTHREAD_NAME.match(comm)) and exe:
                sha = self.grab(f"/proc/{pid}/exe", f"fake-kthread-{pid}", "kthread masquerade")
                self.add("critical", "process", "kthread-masquerade",
                         f"Process {pid} poses as kernel thread '{r.get('argv0') or comm}' "
                         f"but runs {exe}", ["T1036.004"],
                         "Kernel threads have no executable. A user process named like "
                         "[kworker/0:1] is hiding in plain sight - a classic implant trick.",
                         "", dict(ev, sha256=sha), key)
                self._pflag(pid, "fake-kthread")
            if SUSPECT_CMD.search(cmd):
                self.add("high", "process", "suspicious-cmdline",
                         f"Suspicious command line: {cmd[:120]}", ["T1059.004"],
                         "Matches download-and-execute, reverse-shell, decoding or miner "
                         "patterns.", "", ev, key)
                self._pflag(pid, "suspicious-cmd")
            if MINER_RE.search(f"{comm} {exe} {cmd}"):
                self.grab(f"/proc/{pid}/exe", f"miner-{comm}-{pid}", "miner")
                self.add("critical", "process", "miner",
                         f"Cryptominer indicators in {comm} ({pid})", ["T1496"],
                         "Name or arguments match known Monero miners / mining pools.",
                         "", ev, key)
                self._pflag(pid, "miner")
            elif (r["cpu_pct"] or 0) >= 70 and exe and not self.owner(exe):
                self.add("medium", "process", "high-cpu-unpackaged",
                         f"{comm} ({pid}) uses {r['cpu_pct']}% CPU and is not from a package",
                         ["T1496"], "Sustained CPU burn by an unpackaged binary is the "
                         "commonest sign of a cryptominer.", "", ev, key)
                self._pflag(pid, "cpu")
            fd0, fd1 = r["fd012"].get("0", ""), r["fd012"].get("1", "")
            # only TCP/UDP sockets count: every systemd service has a unix
            # socket to journald as stdout
            if fd0[8:-1] in inet or fd1[8:-1] in inet:
                if comm in SHELLS or comm in NET_TOOLS or INTERP.match(comm):
                    crit = comm in SHELLS or comm in NET_TOOLS
                    self.add("critical" if crit else "high", "process", "reverse-shell",
                             f"{comm} ({pid}) has its stdin/stdout wired to a network socket",
                             ["T1059.004"], "An interactive shell or interpreter whose "
                             "terminal is a socket is how reverse and bind shells look from "
                             "the inside.", "Check the Network tab for the peer address.",
                             dict(ev, stdin=fd0, stdout=fd1), key)
                    self._pflag(pid, "socket-shell")
            if comm in SHELLS or comm in NET_TOOLS:
                anc = self._ancestors(pid)
                svc = next((a for a in anc if SERVICE_PARENT.match(a["comm"] or "")), None)
                if svc or r["user"] in SERVICE_USERS:
                    via = f"{svc['comm']} ({svc['pid']})" if svc else f"user {r['user']}"
                    self.add("high", "process", "service-spawned-shell",
                             f"{comm} ({pid}) spawned under {via}", ["T1505.003", "T1059.004"],
                             "Web servers, databases and service accounts should not run "
                             "shells. This is how web-shell and RCE exploitation shows up. "
                             "(PHP mail() via sh -c sendmail is a known benign exception.)",
                             "", dict(ev, chain=" <- ".join(
                                 f"{a['comm']}({a['pid']})" for a in [r] + anc)), key)
                    self._pflag(pid, "service-shell")
            if r["preload"]:
                libs = [x for x in re.split(r"[\s:]+", r["preload"]) if x]
                unpk = [x for x in libs if not self.owner(x)]
                for x in unpk:
                    self.grab(x, None, "LD_PRELOAD library")
                self.add("high" if unpk else "low", "process", "ld-preload-env",
                         f"{comm} ({pid}) runs with LD_PRELOAD={r['preload'][:80]}",
                         ["T1574.006"], "LD_PRELOAD injects a library into the process - "
                         "userland rootkits and credential stealers use it."
                         + ("" if unpk else " The library is package-owned."),
                         "", dict(ev, ld_preload=r["preload"]), key)
                self._pflag(pid, "ld-preload")
            if r["tracer"]:
                tr = self.procs.get(r["tracer"], {})
                benign = (tr.get("comm") or "") in ("gdb", "strace", "ltrace", "lldb", "rr")
                self.add("low" if benign else "medium", "process", "ptraced",
                         f"{comm} ({pid}) is being traced by {tr.get('comm', '?')} "
                         f"({r['tracer']})", ["T1055.008"],
                         "ptrace attachment is used by debuggers - and by injectors and "
                         "credential sniffers (e.g. reading sshd memory).", "",
                         dict(ev, tracer=tr.get("cmdline")), key)
            if (r.get("cwd") or "").startswith(WW_DIRS) or r.get("cwd") in ("/tmp", "/dev/shm", "/var/tmp"):
                self.add("medium", "process", "cwd-world-writable",
                         f"{comm} ({pid}) works inside {r['cwd']}", [],
                         "Payloads are often unpacked and run from a world-writable "
                         "working directory.", "", ev, key)
            if r["bpf"] and exe and not self.owner(exe):
                self.add("medium", "process", "bpf-unpackaged",
                         f"{comm} ({pid}) holds {r['bpf']} eBPF program(s) and is not from a "
                         f"package", ["T1205.002"], "eBPF backdoors (BPFDoor and kin) and "
                         "eBPF rootkits load socket filters / kprobes from unpackaged "
                         "binaries.", "", ev, key)
            elif SUSPECT_INLINE.search(cmd + " ") and r["user"] in SERVICE_USERS:
                self.add("medium", "process", "inline-interpreter",
                         f"Inline interpreter run by {r['user']}: {cmd[:100]}", ["T1059.004"],
                         "", "", ev, key)
            if exe and not exe.startswith("/memfd:") and not self.owner(exe):
                unpackaged.setdefault(exe, []).append(pid)

        if unpackaged and self.owned():
            self.add("info", "process", "unpackaged-running",
                     f"{len(unpackaged)} running executable(s) are not owned by any package",
                     [], "Not malicious by itself (vendor agents, /usr/local, containers), but "
                     "this is the short list to eyeball when hunting.", "",
                     {"executables": {e: sorted(p)[:8] for e, p in sorted(unpackaged.items())}},
                     "unpackaged")
        rows = []
        for pid, r in sorted(self.procs.items()):
            rows.append([pid, r["ppid"], r["user"], r["comm"], r["exe"] or "",
                         r["cmdline"], iso(r["start"]), r["cpu_pct"], r["rss_kb"],
                         ("kthread" if r["kthread"] else self.owner(r["exe"]) or "")
                         if r["exe"] or r["kthread"] else "", self.pflags.get(pid, []),
                         "" if r["kthread"] else (exe_sha256(pid, self.hcache) or "")])
        self.hostinfo["executables_hashed"] = len({v for v in self.hcache.values() if v})
        self.table("processes", "Running processes", "process",
                   ["pid", "ppid", "user", "comm", "exe", "cmdline", "started", "cpu%",
                    "rss_kb", "package", "flags", "sha256"], rows, key=[2, 3, 4, 5])

    def c_hidden_pids(self):
        if os.geteuid() != 0:
            return
        visible = {int(x) for x in os.listdir("/proc") if x.isdigit()}
        pid_max = int((self.read("/proc/sys/kernel/pid_max") or "32768").strip())
        top = pid_max if self.deep else min(pid_max, max(visible | {0}) + 131072)
        cand = []
        for pid in range(1, top + 1):
            if pid in visible:
                continue
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            except PermissionError:
                pass
            cand.append(pid)
        visible = {int(x) for x in os.listdir("/proc") if x.isdigit()}
        for pid in cand:
            if pid in visible:
                continue                   # started while we scanned
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue                   # exited while we scanned
            except PermissionError:
                pass
            st = self.read(f"/proc/{pid}/status")
            m = re.search(r"^Tgid:\s*(\d+)", st or "", re.M)
            if m and int(m.group(1)) != pid:
                continue                   # a thread id, not a process
            name = (re.search(r"^Name:\s*(.*)$", st or "", re.M) or [None, "?"])[1]
            self.add("critical", "process", "hidden-pid",
                     f"Process {pid} ({name}) exists but is hidden from /proc listing",
                     ["T1014"], "The PID answers kill(0) but is missing from the /proc "
                     "directory listing - the signature of a getdents-hooking rootkit.",
                     "Treat the host as rootkitted: acquire memory (AVML) and image the disk.",
                     {"pid": pid, "name": name,
                      "cmdline": (self.read(f"/proc/{pid}/cmdline") or "").replace("\0", " ")},
                     f"{name}")
        self.hostinfo["pid_scan"] = f"1..{top}"

    # ------------------------------------------------------------- network
    def c_network(self):
        # a socket shared by several processes: credit the lowest PID (the master of a
        # prefork server), but never systemd when a real service shares it (socket
        # activation: PID 1 holds every activated listener)
        inode2pid = {i: min((x for x in p if x != 1), default=1)
                     for i, p in self.inode_pids.items()}
        listen, conns = scan_sockets(inode2pid, self.procs)

        def bad_exe(r):
            e = (r or {}).get("exe") or ""
            return e.startswith(("/memfd:",) + WW_DIRS) or (r or {}).get("exe_deleted")

        lrows = []
        for (proto, ip, port), l in sorted(listen.items(), key=lambda x: (x[0][2], x[0][0])):
            pr = self.procs.get(l["pid"])
            flags = []
            pk = self.owner(l["exe"]) if l.get("exe") else None
            ev = {"proto": proto, "bind": f"{ip}:{port}", "pid": l["pid"], "comm": l["comm"],
                  "exe": l.get("exe"), "cmdline": l.get("cmdline"), "user": l.get("user")}
            k = f"{proto}|{port}|{l.get('exe')}"
            if pr and bad_exe(pr):
                flags.append("bad-exe")
                self.add("critical", "network", "listener-bad-exe",
                         f"{proto}/{port} is served by {l['comm']} running from "
                         f"{pr['exe']}", ["T1071"], "A network service backed by a deleted, "
                         "memory-only or /tmp binary is a backdoor until proven otherwise.",
                         "", ev, k)
            elif (l.get("comm") or "") in SHELLS | NET_TOOLS:
                flags.append("bind-shell")
                self.add("high", "network", "listener-shell-tool",
                         f"{l['comm']} is listening on {proto} {ip}:{port}", ["T1059.004"],
                         "Shells and netcat/socat do not normally listen - this is how a "
                         "bind shell looks.", "", ev, k)
            elif l.get("exe") and not pk and ip in ("0.0.0.0", "::") and self.owned():
                flags.append("unpackaged")
            lrows.append([proto, ip, port, l["pid"] or "", l.get("comm") or "?",
                          l.get("user") or "", l.get("exe") or "", (l.get("cmdline") or "")[:200],
                          pk or "", (exe_sha256(l["pid"], self.hcache) or "") if l["pid"] else "",
                          flags])
        self.table("listeners", "Listening sockets", "network",
                   ["proto", "addr", "port", "pid", "comm", "user", "exe", "cmdline", "package",
                    "sha256", "flags"], lrows, key=[0, 1, 2, 4])
        # a connection whose local port is one we listen on was opened BY the peer
        lports = {(pr_, port) for (pr_, _, port) in listen}

        self.conn_list = list(conns.values())
        crows = []
        for key, c in sorted(conns.items(), key=lambda x: (is_private(x[1]["raddr"]), x[0])):
            ext = not is_private(c["raddr"])
            pr = self.procs.get(c["pid"])
            flags = []
            ev = {"proto": c["proto"], "local": f"{c['laddr']}:{c['lport']}",
                  "remote": f"{c['raddr']}:{c['rport']}", "state": c["state"], "pid": c["pid"],
                  "comm": c["comm"], "exe": c.get("exe"), "cmdline": c.get("cmdline")}
            if ext and pr and bad_exe(pr):
                flags.append("bad-exe")
                self.add("high", "network", "c2-candidate",
                         f"{c['comm']} ({c['pid']}) from {pr['exe']} talks to "
                         f"{c['raddr']}:{c['rport']}", ["T1071"],
                         "An outbound session from a deleted / memory-only / /tmp binary is a "
                         "command-and-control candidate. Block and look up the address.",
                         "", ev, f"{pr['exe']}|{c['raddr']}|{c['rport']}")
            if ext:
                flags.append("external")
            if c["pid"] in self.pflags:
                flags += self.pflags[c["pid"]]
            direction = "inbound" if (c["proto"], c["lport"]) in lports else "outbound"
            par = self.procs.get((pr or {}).get("ppid"), {})
            crows.append([c["proto"], direction, f"{c['laddr']}:{c['lport']}", c["raddr"],
                          c["rport"], c["state"], c["pid"] or "", c["comm"] or "?",
                          c.get("user") or "", c.get("exe") or "",
                          (c.get("cmdline") or "")[:200],
                          f"{par.get('comm')} ({pr['ppid']})" if pr and par else "",
                          (self.owner(c["exe"]) or "") if c.get("exe") else "",
                          (exe_sha256(c["pid"], self.hcache) or "") if c["pid"] else "",
                          flags])
        self.table("connections", "Network connections", "network",
                   ["proto", "direction", "local", "remote", "rport", "state", "pid", "process",
                    "user", "exe", "cmdline", "parent", "package", "sha256", "flags"], crows,
                   key=[0, 1, 3, 4, 9],
                   note="direction: outbound = this host's process opened the connection; "
                        "inbound = the remote side connected to a port this host listens on.")

        # raw + packet sockets: sniffers and BPFDoor-style magic-packet backdoors
        benign = {"dhclient", "dhcpcd", "NetworkManager", "systemd-network", "systemd-networkd",
                  "lldpd", "wpa_supplicant", "keepalived", "arpwatch", "hostapd", "dnsmasq",
                  "bird", "ping", "ping6", "dhcpd", "kea-dhcp4", "isc-dhcp-server"}
        sniff = {"tcpdump", "tshark", "dumpcap", "wireshark", "suricata", "zeek", "snort",
                 "Suricata-Main", "W#01-wlan0"}
        srows = []
        for kind, path, inode_col in (("raw", "/proc/net/raw", 9), ("raw6", "/proc/net/raw6", 9),
                                      ("packet", "/proc/net/packet", 8)):
            for line in (self.read(path) or "").splitlines()[1:]:
                f = line.split()
                if len(f) <= inode_col:
                    continue
                pids = sorted(self.inode_pids.get(f[inode_col], ()))
                for pid in pids or [None]:
                    r = self.procs.get(pid, {})
                    comm = r.get("comm") or "?"
                    srows.append([kind, pid or "", comm, r.get("exe") or "", r.get("user") or ""])
                    if comm in benign or (comm.startswith("W#") or comm == "?"):
                        continue
                    sev = "low" if comm in sniff or "suricata" in comm.lower() else (
                        "high" if kind == "packet" else "medium")
                    self.add(sev, "network", "raw-socket",
                             f"{comm} ({pid}) holds a {kind} socket", ["T1040", "T1205.002"],
                             "Raw/packet sockets see traffic below the TCP stack. Sniffers "
                             "use them, and so do magic-packet backdoors such as BPFDoor, "
                             "which never open a listening port.", "",
                             self._pev(r) if r else {"pid": pid},
                             f"{kind}|{r.get('exe')}")
        self.table("raw_sockets", "Raw and packet sockets", "network",
                   ["type", "pid", "comm", "exe", "user"], srows, key=[0, 2, 3])

        irows = []
        for ifc in self.ls("/sys/class/net"):
            try:
                flags = int((self.read(f"/sys/class/net/{ifc}/flags") or "0").strip(), 16)
            except ValueError:
                continue
            promisc = bool(flags & 0x100)
            bridged = os.path.exists(f"/sys/class/net/{ifc}/brport")
            irows.append([ifc, "yes" if promisc else "", "bridge port" if bridged else ""])
            if promisc and not bridged:
                self.add("medium", "network", "promiscuous",
                         f"Interface {ifc} is in promiscuous mode", ["T1040"],
                         "Promiscuous mode captures traffic not addressed to this host - "
                         "a sniffer is (or was) running.", "", {"interface": ifc}, ifc)
        self.table("interfaces", "Network interfaces", "network",
                   ["interface", "promiscuous", "note"], irows)

    # -------------------------------------------------------------- kernel
    def c_kernel(self):
        loaded = {}
        for line in (self.read("/proc/modules") or "").splitlines():
            f = line.split()
            if len(f) >= 5:
                loaded[f[0]] = f
        sysmods = {m for m in self.ls("/sys/module")
                   if os.path.exists(f"/sys/module/{m}/initstate")}
        ksym = set()
        try:
            with open("/proc/kallsyms", errors="replace") as fh:
                for line in fh:
                    if line.endswith("]\n"):
                        ksym.add(line[line.rfind("[") + 1:-2])
        except OSError:
            pass
        ksym = {m for m in ksym if not m.startswith("__builtin") and m not in ("bpf",)}
        for m in sorted((sysmods | ksym) - set(loaded)):
            src = "/sys/module" if m in sysmods else "/proc/kallsyms"
            self.add("critical", "kernel", "hidden-module",
                     f"Kernel module '{m}' is loaded but hidden from /proc/modules",
                     ["T1014", "T1547.006"], f"The module is visible in {src} but has removed "
                     "itself from the module list - what LKM rootkits (Diamorphine, Reptile, "
                     "PUMAKIT...) do.", "Acquire memory (AVML) before rebooting.",
                     {"module": m, "seen_in": src}, m)
        for m in sorted(set(loaded) | sysmods):
            if ROOTKIT_RE.search(m):
                self.add("critical", "kernel", "rootkit-module-name",
                         f"Kernel module named like a known rootkit: {m}", ["T1014"],
                         "", "", {"module": m}, m)

        rel = os.uname().release
        have_tree = os.path.isdir(f"/lib/modules/{rel}")
        if not have_tree:
            self.errors.append({"check": "kernel", "error":
                                f"/lib/modules/{rel} not present (container, or kernel package "
                                "removed) - module file/ownership checks skipped"})
        files = {}
        for dp, dn, fn in os.walk(f"/lib/modules/{rel}"):
            for f in fn:
                m = re.match(r"(.+?)\.ko(\.(xz|zst|gz))?$", f)
                if m:
                    files.setdefault(m.group(1).replace("-", "_"), os.path.join(dp, f))
        rows = []
        for m, f in sorted(loaded.items()):
            path = files.get(m)
            pk = self.owner(path) if path else None
            flags = []
            if not path and not have_tree:
                pass
            elif not path:
                flags.append("no-file")
                self.add("high", "kernel", "module-no-file",
                         f"Loaded module '{m}' has no .ko file under /lib/modules/{rel}",
                         ["T1547.006"], "A module loaded from an unusual path (or deleted "
                         "after insmod) is how many rootkits are installed.", "",
                         {"module": m, "size": f[1], "state": f[4]}, m)
            elif not pk and self.owned():
                flags.append("dkms" if "/updates/" in path or "/extra/" in path else "unpackaged")
                if flags[-1] == "unpackaged":
                    self.add("medium", "kernel", "module-unpackaged",
                             f"Loaded module '{m}' is not owned by any package ({path})",
                             ["T1547.006"], "Out-of-tree modules are normal for DKMS drivers, "
                             "security agents and GPUs - verify this one is expected.", "",
                             {"module": m, "file": path}, m)
            rows.append([m, int(f[1]), f[2], f[3].strip(",-") or "", f[4], path or "",
                         pk or "", flags])
        self.table("modules", "Loaded kernel modules", "kernel",
                   ["module", "size", "refs", "used_by", "state", "file", "package", "flags"],
                   rows, key=[0, 5])

        t = self.hostinfo.get("tainted", 0)
        if t:
            bits = [(b, TAINT.get(b, (f"bit{b}", "other", "info"))) for b in range(32) if t >> b & 1]
            worst = min((x[1][2] for x in bits), key=lambda s: SEV_RANK[s])
            desc = ", ".join(f"{x[1][0]} ({x[1][1]})" for x in bits)
            self.hostinfo["tainted_flags"] = desc
            if worst != "info":
                self.add(worst, "kernel", "kernel-tainted", f"Kernel is tainted: {desc}",
                         ["T1547.006"], "Taint flags record that unsigned, forced or "
                         "out-of-tree code entered the kernel since boot.", "",
                         {"tainted": t, "flags": desc}, desc)
        pins = []
        for dp, dn, fn in os.walk("/sys/fs/bpf"):
            pins += [os.path.join(dp, f) for f in fn]
        if pins:
            self.table("bpf_pins", "Pinned eBPF objects", "kernel", ["path"],
                       [[p] for p in pins[:500]])

    # ------------------------------------------------------------ accounts
    def c_accounts(self):
        shadow = {}
        for line in (self.read("/etc/shadow") or "").splitlines():
            f = line.split(":")
            if len(f) >= 3:
                shadow[f[0]] = f
        groups, gmembers = {}, defaultdict(set)
        for line in (self.read("/etc/group") or "").splitlines():
            f = line.split(":")
            if len(f) >= 4:
                groups[f[2]] = f[0]
                for u in filter(None, f[3].split(",")):
                    gmembers[u].add(f[0])
        seen_uid = defaultdict(list)
        rows = []
        for line in (self.read("/etc/passwd") or "").splitlines():
            f = line.split(":")
            if len(f) < 7 or line.startswith("#"):
                continue
            name, pw, uid, gid, gecos, home, sh = f[:7]
            try:
                uid, gid = int(uid), int(gid)
            except ValueError:
                continue
            login = bool(sh) and not sh.endswith(NOLOGIN)
            u = {"name": name, "uid": uid, "gid": gid, "home": home, "shell": sh,
                 "login": login}
            self.users.append(u)
            seen_uid[uid].append(name)
            if groups.get(str(gid)):
                gmembers[name].add(groups[str(gid)])
            sf = shadow.get(name)
            state = "?"
            if sf:
                h = sf[1]
                state = ("empty" if h == "" else "locked" if h[:1] in ("!", "*") else
                         "set" if h.startswith("$") else "other")
                try:
                    chg = int(sf[2]) * 86400 if sf[2] else 0
                except ValueError:
                    chg = 0
                u["pw_changed"] = chg
            u["pw"] = state
            ev = {"user": name, "uid": uid, "gid": gid, "home": home, "shell": sh,
                  "password": state}
            if uid == 0 and name != "root":
                self.add("critical", "accounts", "uid0-account",
                         f"Account '{name}' has UID 0 (root-equivalent)",
                         ["T1136.001", "T1078.003"], "A second UID-0 account is a classic "
                         "backdoor: it is root under a name nobody audits.", "", ev, name)
            if pw not in ("x", "*", "!", "!!", ""):
                self.add("high", "accounts", "passwd-hash",
                         f"Account '{name}' keeps a password hash in /etc/passwd",
                         ["T1136.001"], "Hashes belong in /etc/shadow. Attackers who can "
                         "write /etc/passwd add users this way.", "", ev, name)
            if pw == "" or (sf and sf[1] == "" and login):
                self.add("high", "accounts", "empty-password",
                         f"Account '{name}' has an empty password", ["T1078.003"],
                         "Anyone can log in as this user where password logins are allowed.",
                         "", ev, name)
            if 0 < uid < 1000 and login and name not in ("sync",):
                sev = "high" if state == "set" else "low"
                self.add(sev, "accounts", "service-account-shell",
                         f"Service account '{name}' (uid {uid}) has login shell {sh}"
                         + (" and a password" if state == "set" else ""), ["T1078.003"],
                         "System accounts normally use nologin. Giving one a shell (and a "
                         "password) is a quiet way to keep access.", "", ev, name)
            if login and state == "set" and u.get("pw_changed", 0) >= self.recent:
                self.add("low", "accounts", "password-recent",
                         f"Password for '{name}' was set/changed in the last {self.days} days",
                         ["T1078.003"], "Covers new accounts too (creation sets the date).",
                         "", dict(ev, changed=time.strftime("%Y-%m-%d",
                                                             time.gmtime(u["pw_changed"]))),
                         name)
            priv = sorted(gmembers[name] & {"sudo", "admin", "wheel", "root", "docker", "lxd",
                                            "disk", "shadow", "adm"})
            u["groups"] = priv
            rows.append([name, uid, gid, home, sh, "yes" if login else "", state,
                         time.strftime("%Y-%m-%d", time.gmtime(u["pw_changed"]))
                         if u.get("pw_changed") else "", " ".join(priv)])
            for g in set(priv) & {"docker", "lxd", "disk", "shadow"}:
                if uid != 0:
                    self.add("medium", "accounts", "root-equivalent-group",
                             f"'{name}' is in group '{g}' (root-equivalent)", ["T1078.003"],
                             f"Members of {g} can trivially become root.", "", ev, f"{name}|{g}")
        for uid, names in seen_uid.items():
            if len(names) > 1 and uid != 0:
                self.add("high", "accounts", "duplicate-uid",
                         f"UID {uid} is shared by: {', '.join(names)}", ["T1136.001"], "", "",
                         {"uid": uid, "accounts": names}, str(uid))
        if not shadow and os.geteuid() == 0:
            self.errors.append({"check": "accounts", "error": "/etc/shadow unreadable or empty"})
        self.table("users", "Local accounts", "accounts",
                   ["user", "uid", "gid", "home", "shell", "login", "password", "pw changed",
                    "privileged groups"], rows, key=[0, 1, 4, 5, 6, 8])

    def homes(self):
        seen, out = set(), []
        for u in self.users + [{"name": "root", "home": "/root", "uid": 0, "login": True}]:
            h = u.get("home") or ""
            if h and h not in seen and h not in ("/", "/nonexistent", "/dev/null") \
                    and os.path.isdir(self.p(h)):
                seen.add(h)
                out.append(u)
        return out

    # ----------------------------------------------------------------- ssh
    def _sshd_config(self):
        cfg = {}
        files = ["/etc/ssh/sshd_config"] + [
            "/etc/ssh/sshd_config.d/" + f for f in self.ls("/etc/ssh/sshd_config.d")
            if f.endswith(".conf")]
        for fp in files:
            for line in (self.read(fp) or "").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("match "):
                    break
                k, _, v = line.partition(" ")
                cfg.setdefault(k.lower(), (v.strip(), fp))   # first value wins in sshd
        return cfg, files

    def c_ssh(self):
        cfg, files = self._sshd_config()
        akf = (cfg.get("authorizedkeysfile", (".ssh/authorized_keys .ssh/authorized_keys2",))[0]
               ).split()
        rows = []
        key_re = re.compile(r"^(?:(?P<opts>.*?)\s+)?(?P<type>(?:ssh|ecdsa|sk)-[\w@.-]+)\s+"
                            r"(?P<key>[A-Za-z0-9+/=]{40,})(?:\s+(?P<comment>.*))?$")
        for u in self.homes():
            for pat in akf:
                rel = pat.replace("%h", u["home"]).replace("%u", u["name"]).replace("%%", "%")
                path = rel if rel.startswith("/") else os.path.join(u["home"], rel)
                txt = self.read(path)
                if txt is None:
                    continue
                st = self.lstat(path)
                keys = 0
                for line in txt.splitlines():
                    line = line.strip()
                    m = key_re.match(line) if line and not line.startswith("#") else None
                    if not m:
                        continue
                    keys += 1
                    fp_ = ssh_fingerprint(m.group("key"))
                    opts = m.group("opts") or ""
                    flags = []
                    ev = {"user": u["name"], "file": path, "type": m.group("type"),
                          "fingerprint": fp_, "comment": m.group("comment") or "",
                          "options": opts, "modified": iso(st.st_mtime) if st else "?"}
                    if not u.get("login", True):
                        flags.append("nologin-user")
                        self.add("high", "accounts", "ssh-key-nologin-user",
                                 f"SSH key for '{u['name']}' whose shell is {u.get('shell')}",
                                 ["T1098.004"], "Keys planted on service accounts give "
                                 "access that normal user reviews miss (and the shell can "
                                 "be swapped later).", "", ev, f"{path}|{fp_}")
                    if "command=" in opts:
                        flags.append("forced-command")
                    if "environment=" in opts:
                        flags.append("environment")
                        self.add("medium", "accounts", "ssh-key-environment",
                                 f"SSH key for '{u['name']}' sets environment= ({path})",
                                 ["T1098.004", "T1574.006"], "Per-key environment variables "
                                 "(honoured with PermitUserEnvironment) can inject LD_PRELOAD "
                                 "into that key's sessions.", "", ev, f"{path}|{fp_}|env")
                    if path.endswith("authorized_keys2"):
                        flags.append("keys2")
                        self.add("medium", "accounts", "ssh-authorized-keys2",
                                 f"Key in deprecated {path}", ["T1098.004"],
                                 "authorized_keys2 is rarely used legitimately and often "
                                 "overlooked by reviewers.", "", ev, f"{path}|{fp_}")
                    if self.is_recent(st):
                        flags.append("recent")
                    rows.append([u["name"], path, m.group("type"), fp_,
                                 m.group("comment") or "", opts[:80],
                                 iso(st.st_mtime) if st else "", flags])
                if keys and self.is_recent(st):
                    self.add("medium", "accounts", "ssh-keys-recent",
                             f"{path} changed in the last {self.days} days ({keys} key(s))",
                             ["T1098.004"], "Adding a key is the most common way attackers "
                             "keep SSH access after the initial compromise.", "",
                             {"file": path, "modified": iso(st.st_mtime), "keys": keys}, path)
        self.table("ssh_keys", "SSH authorized keys", "accounts",
                   ["user", "file", "type", "fingerprint", "comment", "options", "modified",
                    "flags"], rows, key=[0, 1, 3])

        crow = [[k, v[0], v[1]] for k, v in sorted(cfg.items())]
        self.table("sshd_config", "Effective sshd settings (global section)", "accounts",
                   ["directive", "value", "file"], crow, key=[0, 1])
        chk = (("permitemptypasswords", "yes", "high", "Empty passwords are accepted over SSH"),
               ("permitrootlogin", "yes", "medium", "Root may log in over SSH with a password"),
               ("authorizedkeyscommand", None, "medium",
                "AuthorizedKeysCommand is set - keys come from a program"),
               ("authorizedkeysfile", None, "low", "AuthorizedKeysFile is non-default"))
        for k, want, sev, title in chk:
            if k in cfg and (want is None or cfg[k][0].lower() == want):
                if k == "authorizedkeysfile" and cfg[k][0].split() in (
                        [".ssh/authorized_keys"], [".ssh/authorized_keys", ".ssh/authorized_keys2"]):
                    continue
                self.add(sev, "accounts", "sshd-config", f"{title} ({cfg[k][1]})",
                         ["T1021.004", "T1098.004"], "", "",
                         {"directive": k, "value": cfg[k][0], "file": cfg[k][1]}, k)
        for fp in files[1:]:
            if self.owned() and not self.owner(fp):
                st = self.lstat(fp)
                if self.is_recent(st):
                    self.add("low", "accounts", "sshd-dropin-recent",
                             f"New sshd drop-in {fp}", ["T1021.004"], "", "",
                             {"file": fp, "modified": iso(st.st_mtime)}, fp)

    # ---------------------------------------------------------------- sudo
    def c_sudo(self):
        files = ["/etc/sudoers"] + ["/etc/sudoers.d/" + f for f in self.ls("/etc/sudoers.d")
                                    if "." not in f and not f.endswith("~")]
        rows = []
        for fp in files:
            txt = self.read(fp)
            if txt is None:
                continue
            pk = self.owner(fp)
            st = self.lstat(fp)
            if fp != "/etc/sudoers" and not pk and self.owned() and self.is_recent(st):
                self.add("medium", "accounts", "sudoers-dropin-recent",
                         f"sudoers drop-in {fp} added/changed in the last {self.days} days",
                         ["T1548.003"], "", "", {"file": fp, "modified": iso(st.st_mtime)}, fp)
            for line in txt.replace("\\\n", " ").splitlines():
                s = line.strip()
                if not s or (s.startswith("#") and not s.startswith(("#include", "#includedir"))):
                    continue
                rows.append([fp, s[:160], pk or ""])
                low = s.lower()
                ev = {"file": fp, "line": s}
                if s.startswith("Defaults"):
                    if "!authenticate" in low:
                        self.add("high", "accounts", "sudo-no-auth",
                                 f"sudo authentication disabled globally ({fp})",
                                 ["T1548.003"], "", "", ev, s)
                    if re.search(r"env_keep.*\bLD_(PRELOAD|LIBRARY_PATH)", s):
                        self.add("high", "accounts", "sudo-env-keep-ld",
                                 f"sudo keeps LD_PRELOAD/LD_LIBRARY_PATH ({fp})",
                                 ["T1548.003", "T1574.006"], "Lets any sudo user load a "
                                 "library into root processes.", "", ev, s)
                    continue
                if re.match(r"^(User|Runas|Host|Cmnd)_Alias", s) or s.startswith(("@", "#")):
                    continue
                who = s.split()[0]
                if "NOPASSWD" in s and re.search(r"(NOPASSWD:\s*ALL|=\s*\(.*\)\s*NOPASSWD:\s*ALL)\s*$", s):
                    self.add("medium", "accounts", "sudo-nopasswd-all",
                             f"'{who}' gets passwordless root via sudo ({fp})", ["T1548.003"],
                             "Anyone who gets this account's session is root without a "
                             "password. Common in cloud images (ubuntu/admin users).", "", ev, s)
        self.table("sudoers", "sudoers rules", "accounts", ["file", "rule", "package"], rows,
                   key=[0, 1])

    # ----------------------------------------------------------------- PAM
    def c_pam(self):
        rows = []
        for fn in self.ls("/etc/pam.d"):
            fp = "/etc/pam.d/" + fn
            for line in (self.read(fp) or "").splitlines():
                m = re.match(r"^\s*-?(auth|account|password|session)\s+(\[[^\]]*\]|\S+)\s+"
                             r"(\S+)(.*)$", line)
                if not m:
                    continue
                typ, ctl, mod, args = m.groups()
                rows.append([fn, typ, ctl, mod, args.strip()[:100]])
                ev = {"file": fp, "line": line.strip()}
                if "pam_exec" in mod:
                    self.add("high", "persistence", "pam-exec",
                             f"pam_exec runs a program during {typ} ({fp})", ["T1556.003"],
                             "pam_exec hands every login's credentials/context to a script - "
                             "a well-known credential-harvesting backdoor.", "", ev, line.strip())
                if mod.startswith("/") and not self.owner(mod):
                    self.grab(mod, None, "PAM module by absolute path")
                    self.add("high", "persistence", "pam-abs-module",
                             f"PAM loads unpackaged module by path: {mod} ({fp})",
                             ["T1556.003"], "", "", ev, line.strip())
                if "pam_permit" in mod and typ == "auth" and (
                        ctl == "sufficient" or "success=done" in ctl):
                    self.add("high", "persistence", "pam-permit-auth",
                             f"pam_permit grants auth in {fp}", ["T1556.003"],
                             "pam_permit always succeeds - in an auth stack it means any "
                             "password works.", "", ev, line.strip())
        self.table("pam", "PAM stack entries", "persistence",
                   ["file", "type", "control", "module", "args"], rows)
        if not self.owned():
            return
        dirs = set()
        for pat in ("/lib/*/security", "/usr/lib/*/security", "/lib/security",
                    "/usr/lib/security", "/lib64/security", "/usr/lib64/security"):
            dirs.update(os.path.realpath(d) for d in glob.glob(self.p(pat)))
        for d in sorted(dirs):
            for fn in sorted(os.listdir(d)):
                if not fn.endswith(".so"):
                    continue
                path = self.hostpath(os.path.join(d, fn))
                if not self.owner(path):
                    sha = self.grab(path, None, "unpackaged PAM module")
                    self.add("critical", "persistence", "pam-module-unpackaged",
                             f"Unpackaged PAM module {path}", ["T1556.003"],
                             "A PAM .so that no package installed is the textbook "
                             "SSH/login backdoor (master password + credential logging).",
                             "", {"file": path, "sha256": sha}, path)

    # ------------------------------------------------------ dynamic linker
    def c_preload(self):
        txt = self.read("/etc/ld.so.preload")
        if txt:
            libs = [x for x in re.split(r"[\s:]+", re.sub(r"#.*", "", txt)) if x]
            for lib in libs:
                pk = self.owner(lib)
                sha = self.grab(lib, None, "/etc/ld.so.preload")
                self.add("medium" if pk else "critical", "persistence", "ld-so-preload",
                         f"/etc/ld.so.preload loads {lib} into every process"
                         + (f" (package {pk})" if pk else ""), ["T1574.006", "T1014"],
                         "Every dynamically linked program loads this library first. Userland "
                         "rootkits (Azazel, Jynx, bdvl, libprocesshider) live here and hide "
                         "files, processes and connections from ps/ls/ss.",
                         "Note: the hiding also fools ordinary tools - trust this tool's "
                         "/proc-based process list over ps.",
                         {"file": "/etc/ld.so.preload", "library": lib, "package": pk,
                          "sha256": sha}, lib)
        env = self.read("/etc/environment") or ""
        if re.search(r"^\s*LD_(PRELOAD|LIBRARY_PATH)\s*=", env, re.M):
            self.add("high", "persistence", "environment-ld",
                     "/etc/environment sets LD_PRELOAD/LD_LIBRARY_PATH", ["T1574.006"],
                     "", "", {"file": "/etc/environment"}, "env")
        rows = []
        for fn in ["/etc/ld.so.conf"] + ["/etc/ld.so.conf.d/" + f for f in self.ls("/etc/ld.so.conf.d")]:
            for line in (self.read(fn) or "").splitlines():
                s = line.strip()
                if not s or s.startswith("#") or s.startswith("include"):
                    continue
                rows.append([fn, s, self.owner(fn) or ""])
                if s.startswith(WW_DIRS) or s in ("/tmp", "/dev/shm", "/var/tmp") \
                        or s.startswith("/home/"):
                    self.add("high", "persistence", "ld-so-conf-ww",
                             f"Library search path {s} is user-writable ({fn})", ["T1574.006"],
                             "", "", {"file": fn, "dir": s}, f"{fn}|{s}")
        self.table("ld_so_conf", "Dynamic linker search paths", "persistence",
                   ["file", "directory", "package"], rows)

    # ---------------------------------------------------------- cron / at
    def _scan_cmd(self, cmd, cat, check, where, mitre, ev, key):
        if SUSPECT_CMD.search(cmd):
            self.add("high", cat, check, f"Suspicious command in {where}: {cmd[:110]}", mitre,
                     "Matches download-and-execute, reverse-shell, decoding or miner patterns.",
                     "", ev, key)
            return "suspicious"
        first = cmd.split()[0] if cmd.split() else ""
        if first.startswith(WW_DIRS):
            self.add("high", cat, check, f"{where} executes from world-writable {first}", mitre,
                     "Scheduled/boot-time execution of a file in /tmp or /dev/shm is a "
                     "persistence pattern used by miners and botnets.", "", ev, key)
            self.grab(first, None, f"executed by {where}")
            return "ww-exec"
        if WW_PATH.search(cmd):
            return "ww-ref"
        return None

    def _cron_row(self, rows, fp, who, sched, cmd, pk, cmds, flags, user_tab, script=None):
        ex = self.describe_exec(cmds)
        if script:                                    # cron.daily/... : the file itself runs
            spk, ssha = self.file_info(script)
            ex["infos"].insert(0, (script, spk, ssha))
            ex["targets"].insert(0, f"{script}  [{spk or 'UNPACKAGED'}]  {ssha[:16]}")
            if not spk:
                ex["unpackaged"].insert(0, script)
            if not spk or not ex["path"]:             # an unpackaged script is the payload
                ex.update(path=script, pkg=spk, sha=ssha)
        reasons = []
        if self.owned():
            if user_tab:
                reasons.append(f"user crontab ({who})")
            elif not pk:
                reasons.append("cron file not installed by any package")
            if ex["unpackaged"]:
                reasons.append("runs unpackaged " + ", ".join(ex["unpackaged"][:3]))
        default = "yes" if self.owned() and not reasons else ("no" if self.owned() else "?")
        if default == "no":
            for t in ex["unpackaged"]:
                self.grab(t, None, f"executed by cron ({fp})")
            if any(t.startswith(WW_DIRS + ("/home/",)) for t in ex["unpackaged"]) \
                    and "ww-exec" not in flags:
                flags.append("ww-exec")
            if ex["unpackaged"]:
                st = self.lstat(fp)
                recent = self.is_recent(st) or any(self.is_recent(self.lstat(t))
                                                   for t in ex["unpackaged"])
                self.add("medium" if recent else "low", "persistence", "cron-nondefault",
                         f"Non-default cron job ({fp}, {who}) runs unpackaged "
                         f"{', '.join(ex['unpackaged'][:2])}", ["T1053.003"],
                         "A scheduled job running a program no package installed. Usually an "
                         "admin or vendor job - confirm it, and check the program's hash/VT.",
                         "", {"file": fp, "user": who, "schedule": sched, "command": cmd,
                              "exec_targets": ex["targets"], "exec_sha256": ex["sha"]},
                         f"{fp}|{cmd}|{ex['path']}")
        rows.append([fp, who, sched, cmd[:200], default, "; ".join(reasons), ex["path"],
                     ex["pkg"], ex["sha"], ex["targets"], pk or "", list(dict.fromkeys(flags))])

    def c_cron(self):
        rows = []
        uids = {u["name"]: u["uid"] for u in self.users}

        def crontab(fp, user=None):
            txt = self.read(fp)
            if txt is None:
                return
            st = self.lstat(fp)
            pk = self.owner(fp)
            n = 0
            for line in txt.splitlines():
                s = line.strip()
                if not s or s.startswith("#") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", s):
                    continue
                f = s.split()
                if s.startswith("@"):
                    sched, rest = f[0], f[1:]
                else:
                    sched, rest = " ".join(f[:5]), f[5:]
                who = user
                if who is None and rest:
                    who, rest = rest[0], rest[1:]
                cmd = " ".join(rest)
                n += 1
                ev = {"file": fp, "user": who, "schedule": sched, "command": cmd}
                flag = self._scan_cmd(cmd, "persistence", "cron-entry", f"cron ({fp})",
                                      ["T1053.003"], ev, f"{fp}|{cmd}")
                flags = [flag] if flag else []
                if flag == "ww-ref":
                    self.add("medium", "persistence", "cron-ww-ref",
                             f"cron entry references a world-writable path ({fp})",
                             ["T1053.003"], "", "", ev, f"{fp}|{cmd}")
                if not pk:
                    flags.append("unpackaged")
                self._cron_row(rows, fp, who or "", sched, cmd, pk, [cmd], flags, user is not None)
            if n and user and 0 < uids.get(user, 0) < 1000:
                self.add("medium", "persistence", "cron-service-account",
                         f"Service account '{user}' has a crontab ({n} entries)",
                         ["T1053.003"], "www-data/nobody crontabs are a favourite way for "
                         "web-shell operators to persist.", "", {"file": fp}, fp)
            if n and not pk and self.is_recent(st) and self.owned():
                self.add("medium", "persistence", "cron-recent",
                         f"cron file {fp} changed in the last {self.days} days",
                         ["T1053.003"], "", "", {"file": fp, "modified": iso(st.st_mtime),
                                                 "entries": n}, fp)

        crontab("/etc/crontab")
        for f in self.ls("/etc/cron.d"):
            if not f.startswith(".") and not f.endswith("~"):
                crontab("/etc/cron.d/" + f)
        for spool in ("/var/spool/cron/crontabs", "/var/spool/cron"):
            for f in self.ls(spool):
                if os.path.isfile(self.p(f"{spool}/{f}")) and not f.startswith("."):
                    crontab(f"{spool}/{f}", user=f)
        for per in ("hourly", "daily", "weekly", "monthly"):
            d = f"/etc/cron.{per}"
            for f in self.ls(d):
                fp = f"{d}/{f}"
                if f.startswith(".") or f == "placeholder":
                    continue
                txt = self.read(fp, 1 << 20) or ""
                pk = self.owner(fp)
                st = self.lstat(fp)
                flags = [] if pk else ["unpackaged"]
                ev = {"file": fp, "package": pk}
                if SUSPECT_CMD.search(txt):
                    flags.append("suspicious")
                    self.add("high", "persistence", "cron-script",
                             f"Suspicious content in cron script {fp}", ["T1053.003"],
                             "", "", dict(ev, match=SUSPECT_CMD.search(txt).group(0)), fp)
                elif not pk and self.owned():
                    self.add("medium" if self.is_recent(st) else "low", "persistence",
                             "cron-script-unpackaged", f"Unpackaged {per} cron script {fp}",
                             ["T1053.003"], "Runs as root on schedule. Verify who installed it.",
                             "", dict(ev, modified=iso(st.st_mtime) if st else "?"), fp)
                self._cron_row(rows, fp, "root", per, "(script)", pk, [], flags, False,
                               script=fp)
        cols = ["source", "user", "schedule", "command", "default", "reason", "exec path",
                "exec package", "exec sha256", "exec targets", "file package", "flags"]
        self.table("cron", "Scheduled jobs (cron)", "persistence", cols, rows,
                   key=[0, 1, 3, 8],
                   note="default = in a package-installed cron file and every program it runs "
                        "is package-owned. User crontabs are never default.")
        self.table("cron_nondefault", "Non-default cron jobs", "persistence", cols,
                   [r for r in rows if r[4] == "no"], key=[0, 1, 3, 8])

        at = []
        for d in ("/var/spool/cron/atjobs", "/var/spool/at"):
            for f in self.ls(d):
                if f.startswith(".") or f == "spool":
                    continue
                txt = self.read(f"{d}/{f}") or ""
                cmd = "\n".join(l for l in txt.splitlines()[-6:] if l.strip() and
                                not l.startswith(("#", "cd ", "export", "umask")))
                at.append([f"{d}/{f}", cmd[:200]])
                self.add("medium", "persistence", "at-job", f"Pending at job {d}/{f}",
                         ["T1053.002"], "at jobs are rare on servers and easy to overlook.",
                         "", {"file": f"{d}/{f}", "tail": cmd}, f"{d}/{f}")
        if at:
            self.table("at_jobs", "Pending at jobs", "persistence", ["file", "command"], at)

    # ------------------------------------------------------------- systemd
    def c_systemd(self):
        sysdirs = ["/etc/systemd/system", "/run/systemd/transient", "/run/systemd/system",
                   "/usr/local/lib/systemd/system",
                   "/lib/systemd/system", "/usr/lib/systemd/system"]
        userdirs = ["/etc/systemd/user", "/usr/local/lib/systemd/user", "/usr/lib/systemd/user"]
        for u in self.homes():
            userdirs += [u["home"] + "/.config/systemd/user", u["home"] + "/.local/share/systemd/user"]
        std_roots = tuple(d + "/" for d in sysdirs + userdirs)
        rows, seen = [], set()
        for scope, dirs in (("system", sysdirs), ("user", userdirs)):
            for d in dirs:
                real = os.path.realpath(self.p(d))
                if real in seen or not os.path.isdir(real):
                    continue
                seen.add(real)
                for name in sorted(os.listdir(real)):
                    fp = f"{d}/{name}"
                    full = os.path.join(real, name)
                    if name.endswith((".wants", ".requires", ".upholds")) and os.path.isdir(full):
                        for ln in os.listdir(full):
                            self.enabled_units.add(re.sub(r"@[^.]*\.", "@.", ln))
                            tgt = readlink(os.path.join(full, ln)) or ""
                            if tgt and not tgt.startswith(std_roots) and tgt.startswith("/") \
                                    and tgt != "/dev/null":
                                self.add("high", "persistence", "systemd-odd-link",
                                         f"{fp}/{ln} enables a unit outside systemd dirs: {tgt}",
                                         ["T1543.002"], "", "", {"link": f"{fp}/{ln}",
                                                                 "target": tgt}, f"{fp}/{ln}")
                        continue
                    if name.endswith(".d") and os.path.isdir(full):
                        if name.endswith((".scope.d", ".slice.d")):
                            continue            # docker/session scopes: runtime, not persistence
                        for dn in sorted(os.listdir(full)):
                            if dn.endswith(".conf"):
                                self._unit(f"{fp}/{dn}", scope, rows, dropin=True)
                        continue
                    if re.search(r"\.(service|timer|socket|path)$", name):
                        self._unit(fp, scope, rows)
        for d in ("/etc/systemd/system-generators", "/usr/local/lib/systemd/system-generators",
                  "/lib/systemd/system-generators", "/usr/lib/systemd/system-generators",
                  "/etc/systemd/user-generators"):
            for g in self.ls(d):
                fp = f"{d}/{g}"
                if self.owned() and not self.owner(fp):
                    self.grab(fp, None, "systemd generator")
                    self.add("high", "persistence", "systemd-generator",
                             f"Unpackaged systemd generator {fp}", ["T1543.002"],
                             "Generators run very early at every boot and on daemon-reload, as "
                             "root, before most logging - a stealthy persistence point.",
                             "", {"file": fp}, fp)
        self.table("systemd", "systemd unit files (raw)", "persistence",
                   ["unit", "scope", "path", "package", "exec", "changed", "flags"], rows,
                   key=[0, 1, 2, 4])
        self._services_view()

    # ------------------------------------------- executable resolution
    PATHDIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
    WRAPPERS = {"nohup", "nice", "ionice", "timeout", "flock", "env", "sudo", "runuser", "su",
                "chronic", "cronic", "setsid", "stdbuf", "exec", "chrt", "taskset", "run-one",
                "systemd-cat", "unbuffer", "xargs", "time"}
    NOT_PROGRAMS = {"cd", "test", "[", "[[", "true", "false", ":", "echo", "exit", "if", "then",
                    "fi", "else", "export", "set", "unset", "return", "sleep", "printf", "do",
                    "done", "while", "for", "local", "read"}

    def md5map(self):
        """dpkg's recorded MD5 for every packaged file: {'/usr/lib/...': md5}"""
        if self._md5 is None:
            self._md5 = {}
            for mf in glob.glob(self.p("/var/lib/dpkg/info") + "/*.md5sums"):
                try:
                    with open(mf, errors="replace") as fh:
                        for line in fh:
                            md5, _, rel = line.rstrip("\n").partition("  ")
                            if rel:
                                self._md5["/" + rel] = md5
                except OSError:
                    pass
        return self._md5

    def pkg_modified(self, path):
        """True when dpkg has an MD5 for this packaged file and the disk copy differs."""
        m = self.md5map()
        want = next((m[v] for v in self._variants(path) if v in m), None)
        if not want:
            return False
        try:
            return _md5(self.p(path)) != want
        except OSError:
            return False

    def which(self, prog):
        if not prog or "$" in prog or "%" in prog:
            return None
        if "/" in prog:
            if not prog.startswith("/"):
                return None
            return prog if os.path.isfile(self.p(prog)) else None
        for d in self.PATHDIRS:
            if os.path.isfile(self.p(f"{d}/{prog}")):
                return f"{d}/{prog}"
        return None

    def exec_targets(self, cmd, depth=0):
        """Programs a command line really runs, unwrapping sh -c, nohup, env, sudo,
        'python script.py', 'cd x && y' ... -> list of absolute host paths."""
        out = []
        for part in re.split(r"\s*(?:&&|\|\||;|\||&(?!>))\s*", cmd or ""):
            try:
                toks = shlex.split(part, comments=False, posix=True)
            except ValueError:
                toks = part.split()
            i = 0
            while i < len(toks):
                t = toks[i]
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):
                    i += 1
                    continue
                w = os.path.basename(t)
                if w not in self.WRAPPERS:
                    break
                i += 1
                while i < len(toks):                 # the wrapper's own options
                    o = toks[i]
                    if o == "--":
                        i += 1
                        break
                    if w == "su" and o == "-c" and i + 1 < len(toks):
                        if depth < 3:
                            out += self.exec_targets(toks[i + 1], depth + 1)
                        i = len(toks)
                        break
                    if o in ("-u", "-g", "-n", "-w", "-E", "-s", "-k", "-l", "--user",
                             "--group", "--signal", "--kill-after") and w != "env":
                        i += 2
                    elif o.startswith("-") or re.fullmatch(r"\d+(\.\d+)?[smhd]?", o):
                        i += 1
                    elif w == "flock" and o.startswith("/") and not os.access(self.p(o), os.X_OK):
                        i += 1                        # flock's lock file
                    else:
                        break
            if i >= len(toks):
                continue
            prog = toks[i]
            base = os.path.basename(prog)
            # built-ins only when called by bare name: '/tmp/.x/sleep' is a real program
            # (an attacker could otherwise hide a payload by naming it echo/test/sleep)
            if ("/" not in prog and base in self.NOT_PROGRAMS) or prog.startswith(("(", "{", "<", ">")):
                continue
            path = self.which(prog)
            if path:
                out.append(path)
            if base in SHELLS or INTERP.match(base):
                j = i + 1
                while j < len(toks) and toks[j].startswith("-") and toks[j] != "-c":
                    j += 1
                if j < len(toks) and toks[j] == "-c" and j + 1 < len(toks) and depth < 3:
                    out += self.exec_targets(toks[j + 1], depth + 1)
                elif j < len(toks) and toks[j].startswith("/") and os.path.isfile(self.p(toks[j])):
                    out.append(toks[j])                       # the script is the payload
        seen = set()
        return [x for x in out if not (x in seen or seen.add(x))]

    def file_info(self, path):
        """-> (package or '', sha256 or '') for a host path, cached."""
        if path not in self._finfo:
            pk = self.owner(path) or ""
            sha = ""
            try:
                st = os.stat(self.p(path))
                if stat.S_ISREG(st.st_mode) and st.st_size <= 256 << 20:
                    sha = _sha256(self.p(path))
            except OSError:
                pass
            self._finfo[path] = (pk, sha)
        return self._finfo[path]

    def describe_exec(self, commands):
        """Resolve every program behind a list of command lines.
        -> primary path, its package, its sha256, all targets, unpackaged targets"""
        targets = []
        for c in commands:
            for t in self.exec_targets(c):
                if t not in targets:
                    targets.append(t)
        infos = [(t,) + self.file_info(t) for t in targets]
        unpk = [t for t, pk, _ in infos if not pk]
        # the payload: first unpackaged target, else the last one (sh -c x -> x)
        prim = next((x for x in infos if not x[1]), infos[-1] if infos else ("", "", ""))
        return {"path": prim[0], "pkg": prim[1], "sha": prim[2], "unpackaged": unpk,
                "targets": [f"{t}  [{pk or 'UNPACKAGED'}]  {sha[:16]}" for t, pk, sha in infos],
                "infos": infos}

    def _running(self, unit):
        if not self.live:
            return ""
        pids = []
        for pat in (f"/sys/fs/cgroup/system.slice/{unit}/cgroup.procs",
                    f"/sys/fs/cgroup/system.slice/*/{unit}/cgroup.procs",
                    f"/sys/fs/cgroup/systemd/system.slice/{unit}/cgroup.procs"):
            for fp in glob.glob(pat):
                pids += [int(x) for x in (self.read(fp) or "").split() if x.isdigit()]
        if not pids:
            return ""
        p0 = min(pids)
        exe = self.procs.get(p0, {}).get("exe") or readlink(f"/proc/{p0}/exe") or "?"
        return f"pid {p0} {exe}" + (f" (+{len(pids) - 1})" if len(pids) > 1 else "")

    def _services_view(self):
        """One row per effective unit: is it a distribution default or not, and what
        does it really execute?"""
        packaged_names = {os.path.basename(r["file"]) for r in self.unit_recs
                          if r["pkg"] and not r["dropin"]}
        eff = {}
        for r in self.unit_recs:                    # dirs were walked in precedence order
            if r["dropin"]:
                continue
            k = (r["scope"], r["name"])
            if k in eff:
                eff[k]["shadowed"].append(r)        # a lower-priority (often vendor) copy
            else:
                eff[k] = dict(r, shadowed=[], dropins=[])
        for r in self.unit_recs:
            if r["dropin"]:
                k = (r["scope"], r["name"])
                if k in eff:
                    eff[k]["dropins"].append(r)
        rows, nd = [], []
        have_db = bool(self.owned())
        for (scope, name), u in sorted(eff.items(), key=lambda x: (x[0][0], x[0][1])):
            starts = u["start"]
            for d in u["dropins"]:                  # a drop-in ExecStart replaces the unit's
                if d["start"]:
                    starts = [s for s in d["start"] if s] or starts
            cmds = starts + [e for e in u["execs"] if e not in u["start"]]
            for d in u["dropins"]:
                cmds += [e for e in d["execs"] if e not in d["start"]]
            ex = self.describe_exec(cmds)
            reasons, flags = [], list(u["flags"])
            if have_db:
                if not u["pkg"]:
                    vendor = next((s for s in u["shadowed"] if s["pkg"]), None)
                    reasons.append(f"overrides packaged {vendor['file']}" if vendor
                                   else "unit not installed by any package")
                elif self.pkg_modified(u["file"]):
                    reasons.append("packaged unit file modified")
                    flags.append("modified")
                    self.add("high", "persistence", "service-unit-modified",
                             f"Packaged unit {u['file']} was modified ({u['pkg']})",
                             ["T1543.002"], "The unit file no longer matches the copy dpkg "
                             "installed. Attackers edit ExecStart of an existing trusted "
                             "service instead of adding a new one.",
                             f"Diff it against the package (apt-get download {u['pkg']}).",
                             {"unit": u["file"], "package": u["pkg"], "exec": cmds[:4]},
                             u["file"])
                for d in u["dropins"]:
                    if not d["pkg"]:
                        reasons.append(f"drop-in {d['file']}" + (" changes ExecStart"
                                                                if d["start"] else ""))
                if ex["unpackaged"]:
                    reasons.append("runs unpackaged " + ", ".join(ex["unpackaged"][:3]))
            default = have_db and not reasons
            enabled = "yes" if (name in self.enabled_units or
                                re.sub(r"@[^.]*\.", "@.", name) in self.enabled_units) else ""
            running = self._running(name) if name.endswith(".service") else ""
            changed = iso(max(u["st"].st_mtime, u["st"].st_ctime))
            flags = list(dict.fromkeys(flags))
            row = [name, scope, "yes" if default else ("no" if have_db else "?"),
                   "; ".join(reasons), enabled, running, ex["path"], ex["pkg"], ex["sha"],
                   ex["targets"], u["file"], u["pkg"] or "", changed, flags]
            rows.append(row)
            if default or not have_db:
                continue
            nd.append(row)
            ev = {"unit": name, "scope": scope, "unit_file": u["file"], "reason": reasons,
                  "enabled": bool(enabled), "running": running, "exec": cmds[:4],
                  "exec_targets": ex["targets"], "exec_sha256": ex["sha"], "changed": changed}
            for t in ex["unpackaged"]:
                self.grab(t, None, f"executed by non-default service {name}")
            if not u["pkg"]:
                base = re.sub(r"\.(service|timer|socket|path)$", "", name)
                look = difflib.get_close_matches(name, packaged_names - {name}, n=1, cutoff=0.86)
                fake = look or (re.match(r"^(systemd-|dbus-|kworker|kthread|udev|journald|"
                                         r"network-|snapd|cron-|polkit|accounts-daemon|"
                                         r"rsyslog|apparmor|ssh-)", base) and name not in packaged_names)
                if fake:
                    flags.append("masquerade")
                    self.add("high", "persistence", "service-masquerade",
                             f"Unpackaged unit {name} is named like a system service"
                             + (f" ({look[0]})" if look else ""), ["T1036.004", "T1543.002"],
                             "Implants register services named like real ones (systemd-*, "
                             "dbus-*, kworker...) so they blend into systemctl output.",
                             "", ev, f"{scope}|{name}")
            if any(t.startswith(WW_DIRS + ("/home/",)) for t in ex["unpackaged"]):
                flags.append("ww-exec")
                sev = "high"
            elif ex["unpackaged"] and (self.is_recent(u["st"]) or any(
                    self.is_recent(self.lstat(t)) for t in ex["unpackaged"])):
                sev = "medium"
            elif ex["unpackaged"] or "drop-in" in " ".join(reasons) or "overrides" in " ".join(reasons):
                sev = "low"
            else:
                sev = None                       # unpackaged unit file running packaged binaries
            if sev:
                self.add(sev, "persistence", "service-nondefault",
                         f"Non-default service {name}: {'; '.join(reasons)[:120]}",
                         ["T1543.002"], "Not part of the distribution's packages (or changed "
                         "from them). Most are legitimate admin or vendor services - confirm "
                         "each one is expected and check its executable's hash/VT.",
                         "", ev, f"{scope}|{name}|{ex['path']}")
        cols = ["unit", "scope", "default", "reason", "enabled", "running", "exec path",
                "exec package", "exec sha256", "exec targets", "unit file", "unit package",
                "changed", "flags"]
        self.table("services", "Services, timers and sockets (effective units)", "persistence",
                   cols, rows, key=[0, 1, 6, 8],
                   note="default = installed by a package, unit file unmodified (dpkg MD5), no "
                        "unpackaged drop-in, and every program it runs is package-owned.")
        self.table("services_nondefault", "Non-default services", "persistence", cols, nd,
                   key=[0, 1, 6, 8],
                   note="Everything here differs from what the distribution's packages "
                        "installed: new units, overridden or modified units, drop-ins, or "
                        "units running unpackaged programs.")

    def _unit(self, fp, scope, rows, dropin=False):
        st = self.lstat(fp)
        if st is None:
            return
        if stat.S_ISLNK(st.st_mode) and (readlink(self.p(fp)) or "") == "/dev/null":
            return                                  # masked
        txt = self.read(fp, 1 << 20) or ""
        # transient units (systemd-run) store ExecStart={ path=/x ; argv[]=/x args ; ... }
        txt = re.sub(r"^([ \t]*Exec\w*[ \t]*=[ \t]*)\{[^}]*?argv\[\]=([^;}]+)[^}]*\}",
                     lambda m: m.group(1) + m.group(2).strip(), txt, flags=re.M)
        execs = [m.group(2).strip() for m in
                 re.finditer(r"^[ \t]*(Exec\w*)[ \t]*=[ \t]*(.+)$", txt, re.M) if m.group(2).strip()]
        pk = self.owner(fp)
        flags = []
        ev = {"unit": fp, "scope": scope, "package": pk, "exec": execs[:4],
              "changed": iso(max(st.st_mtime, st.st_ctime))}
        home_unit = scope == "user" and fp.startswith(("/home/", "/root/"))
        for ex in execs:
            cmd = ex.lstrip("-@:+!|")
            flag = self._scan_cmd(cmd, "persistence", "systemd-exec", f"unit {fp}",
                                  ["T1543.002"], ev, f"{fp}|{cmd}")
            if flag:
                flags.append(flag)
            first = cmd.split()[0] if cmd.split() else ""
            if first.startswith("/home/") and not home_unit:
                flags.append("home-exec")
                self.add("high", "persistence", "systemd-home-exec",
                         f"System unit {fp} runs a binary from /home: {first}", ["T1543.002"],
                         "", "", ev, f"{fp}|{first}")
        if self.owned() and not pk:
            flags.append("unpackaged")
            if home_unit:
                self.add("medium", "persistence", "systemd-user-unit",
                         f"Per-user systemd unit {fp}", ["T1543.002"],
                         "User units start at login (or at boot with lingering) and are "
                         "outside most admins' view.", "", ev, fp)
            elif self.is_recent(st) and not fp.startswith("/run/"):   # /run is rebuilt each boot
                self.add("medium", "persistence", "systemd-unit-recent",
                         f"Unpackaged {'drop-in' if dropin else 'unit'} {fp} changed in the "
                         f"last {self.days} days", ["T1543.002", "T1053.006"]
                         if fp.endswith(".timer") else ["T1543.002"],
                         "New services and timers are the most common Linux persistence.",
                         "", ev, fp)
        rows.append([os.path.basename(fp) if not dropin else fp.split("/")[-2] + "/" +
                     os.path.basename(fp), scope, fp, pk or "", (execs[0] if execs else "")[:160],
                     iso(max(st.st_mtime, st.st_ctime)), flags])
        self.unit_recs.append({"file": fp, "scope": scope, "pkg": pk, "st": st, "dropin": dropin,
                               "execs": [e.lstrip("-@:+!|") for e in execs],
                               "start": [m.group(1).lstrip("-@:+!|").strip() for m in
                                         re.finditer(r"^[ \t]*ExecStart[ \t]*=[ \t]*(.*)$", txt, re.M)],
                               "name": fp.split("/")[-2][:-2] if dropin else os.path.basename(fp),
                               "flags": flags})

    # ---------------------------------------------------- other autostarts
    def _dir_items(self, d, check, label, mitre, why, sev_unpk="medium", ext=None, want_run=None):
        """Generic: unpackaged / suspicious entries in an autostart directory."""
        out = []
        for f in self.ls(d):
            fp = f"{d}/{f}"
            if f.startswith(".") or f.endswith("~") or (ext and not f.endswith(ext)):
                continue
            st = self.lstat(fp)
            if not st or stat.S_ISDIR(st.st_mode):
                continue
            if self.hostinfo.get("container") and f == "60-unminimize":
                continue                    # Ubuntu minimal image artefact
            txt = self.read(fp, 1 << 20) or ""
            pk = self.owner(fp)
            flags = []
            ev = {"file": fp, "package": pk, "modified": iso(st.st_mtime)}
            m = SUSPECT_CMD.search(txt)
            if m:
                flags.append("suspicious")
                self.add("high", "persistence", check, f"Suspicious content in {label} {fp}",
                         mitre, why, "", dict(ev, match=m.group(0)), fp)
            elif self.owned() and not pk:
                flags.append("unpackaged")
                if want_run is None or re.search(want_run, txt):
                    # recently added -> at least medium
                    sev = min(sev_unpk, "medium", key=lambda s: SEV_RANK[s]) \
                        if self.is_recent(st) else sev_unpk
                    self.add(sev, "persistence", check, f"Unpackaged {label} {fp}", mitre,
                             why, "", ev, fp)
            out.append([label, fp, pk or "", iso(st.st_mtime), flags])
        return out

    def c_autostart(self):
        rows = []
        rc = self.read("/etc/rc.local")
        if rc:
            body = [l for l in rc.splitlines() if l.strip() and not l.strip().startswith("#")
                    and l.strip() not in ("exit 0",)]
            st = self.lstat("/etc/rc.local")
            rows.append(["rc.local", "/etc/rc.local", self.owner("/etc/rc.local") or "",
                         iso(st.st_mtime) if st else "", ["has-commands"] if body else []])
            if body:
                sus = any(SUSPECT_CMD.search(l) or WW_PATH.search(l) for l in body)
                self.add("high" if sus else "medium", "persistence", "rc-local",
                         f"/etc/rc.local runs {len(body)} command(s) at boot", ["T1037.004"],
                         "rc.local is deprecated on systemd hosts; anything in it deserves a "
                         "look.", "", {"file": "/etc/rc.local", "commands": body[:15]}, "rc")
        why_init = "SysV init scripts run as root at boot; unpackaged ones are unusual today."
        rows += self._dir_items("/etc/init.d", "initd-script", "init.d script", ["T1037.004"],
                                why_init, "medium")
        rows += self._dir_items("/etc/update-motd.d", "motd-script", "MOTD script", ["T1546"],
                                "update-motd scripts run as root on every SSH login.", "high")
        rows += self._dir_items("/etc/xdg/autostart", "xdg-autostart", "XDG autostart",
                                ["T1547.013"], "Runs at every desktop login.", "medium", ".desktop")
        for u in self.homes():
            rows += self._dir_items(u["home"] + "/.config/autostart", "xdg-autostart",
                                    "user XDG autostart", ["T1547.013"], "", "medium", ".desktop")
        rows += self._dir_items("/etc/udev/rules.d", "udev-rule", "udev rule", ["T1546.017"],
                                "udev RUN+= commands execute as root on device events.", "high",
                                ".rules", want_run=r"RUN\s*\+?=")
        for d in ("/etc/NetworkManager/dispatcher.d", "/etc/network/if-up.d",
                  "/etc/network/if-pre-up.d", "/etc/ppp/ip-up.d", "/etc/dhcp/dhclient-exit-hooks.d"):
            rows += self._dir_items(d, "network-hook", "network hook", ["T1546"],
                                    "Network hooks run as root whenever an interface changes.",
                                    "medium")
        for f in self.ls("/etc/apt/apt.conf.d"):
            fp = "/etc/apt/apt.conf.d/" + f
            txt = self.read(fp) or ""
            hooks = re.findall(r"(?:APT::Update::(?:Pre|Post)-Invoke(?:-Success)?|DPkg::(?:Pre|Post)"
                               r"-Invoke|DPkg::Pre-Install-Pkgs)\s*\{?\s*\"([^\"]+)\"", txt, re.I)
            if not hooks:
                continue
            if self.hostinfo.get("container") and f.startswith("docker-"):
                continue                    # stock Docker base-image hooks
            pk = self.owner(fp)
            flags = [] if pk else ["unpackaged"]
            sus = [h for h in hooks if SUSPECT_CMD.search(h) or WW_PATH.search(h)]
            if sus or (not pk and self.owned()):
                self.add("high", "persistence", "apt-hook",
                         f"APT hook in {'unpackaged ' if not pk else ''}{fp} runs: {hooks[0][:90]}",
                         ["T1546"], "APT Pre/Post-Invoke hooks run as root on every apt "
                         "update/install - a Debian-specific persistence trick.", "",
                         {"file": fp, "hooks": hooks, "package": pk}, fp)
                flags.append("hook")
            rows.append(["apt hook", fp, pk or "", "", flags])
        for fp in ["/etc/modules"] + ["/etc/modules-load.d/" + f for f in self.ls("/etc/modules-load.d")]:
            for line in (self.read(fp) or "").splitlines():
                s = line.strip()
                if s and not s.startswith(("#", ";")):
                    rows.append(["module autoload", f"{fp}: {s}", self.owner(fp) or "", "", []])
                    if ROOTKIT_RE.search(s):
                        self.add("critical", "kernel", "rootkit-autoload",
                                 f"{fp} autoloads module named like a rootkit: {s}",
                                 ["T1547.006", "T1014"], "", "", {"file": fp, "module": s}, s)
        for f in self.ls("/etc/modprobe.d"):
            fp = "/etc/modprobe.d/" + f
            for line in (self.read(fp) or "").splitlines():
                m = re.match(r"^\s*install\s+(\S+)\s+(.+)$", line)
                if m and not re.match(r"^(/bin/|/usr/bin/)?(true|false)\b|^/s?bin/modprobe|"
                                      r"^/usr/s?bin/modprobe|^/bin/sh -c ['\"]?/s?bin/modprobe",
                                      m.group(2).strip()):
                    self.add("high", "persistence", "modprobe-install",
                             f"modprobe 'install {m.group(1)}' runs {m.group(2)[:80]} ({fp})",
                             ["T1547.006"], "modprobe install directives execute a command "
                             "whenever the module is requested.", "",
                             {"file": fp, "line": line.strip()}, f"{fp}|{m.group(1)}")
        self.table("autostart", "Other autostart locations", "persistence",
                   ["kind", "path", "package", "modified", "flags"], rows, key=[0, 1])

    # ------------------------------------------- other attacker persistence
    PY_BAD = re.compile(r"b64decode|base64|socket|subprocess|os\.system|popen|urllib|urlopen|"
                        r"requests\.|marshal|zlib\.decompress|http\.client|ctypes", re.I)
    PY_WEAK = re.compile(r"exec\s*\(|eval\s*\(|__import__\s*\(|compile\s*\(", re.I)
    PY_BENIGN_PTH = re.compile(r"-nspkg\.pth$|^distutils-precedence\.pth$|^_virtualenv\.pth$|"
                               r"^__editable__|^easy-install\.pth$")

    def conffiles(self):
        """{'/etc/x': md5} recorded by dpkg for every package conffile."""
        if not hasattr(self, "_conff"):
            self._conff = {}
            for line in (self.read("/var/lib/dpkg/status", 256 << 20) or "").splitlines():
                if line.startswith(" /"):
                    f = line.split()
                    if len(f) >= 2 and f[1] != "newconffile" and "obsolete" not in f[2:]:
                        self._conff[f[0]] = f[1]
        return self._conff

    def conf_modified(self, path):
        want = self.conffiles().get(path)
        if not want:
            return False
        try:
            return _md5(self.p(path)) != want
        except OSError:
            return False

    def _lib_lookup(self, name):
        """Find a shared library by file name in the system library directories."""
        for pat in ("/lib/*/{n}", "/usr/lib/*/{n}", "/lib/{n}", "/usr/lib/{n}", "/lib64/{n}",
                    "/usr/lib64/{n}", "/usr/local/lib/{n}"):
            for fp in glob.glob(self.p(pat.format(n=name))):
                return self.hostpath(fp)
        return None

    def c_more_persistence(self):
        rows = []

        def rec(kind, path, detail="", flags=None):
            rows.append([kind, path, self.owner(path) or "", str(detail)[:200], flags or []])

        def sus(text):
            m = SUSPECT_CMD.search(text or "") or WW_PATH.search(text or "")
            return m.group(0) if m else None

        # ---- A. SSH login hooks and trust anchors --------------------------------
        for fp, who in [("/etc/ssh/sshrc", "all users")] + \
                [(f"{u['home']}/.ssh/rc", u["name"]) for u in self.homes()]:
            txt = self.read(fp)
            if txt is None:
                continue
            rec("ssh rc", fp, txt.strip(), ["login-hook"])
            self.add("high" if (sus(txt) or not self.owner(fp)) else "medium", "persistence",
                     "ssh-rc", f"{fp} runs on every SSH login ({who})", ["T1546", "T1098.004"],
                     "sshd executes sshrc / ~/.ssh/rc for each login before the user's shell: "
                     "a quiet hook for re-infection or credential capture. Rarely used "
                     "legitimately.", "", {"file": fp, "content": txt[:600]}, fp)
        cfg, _ = self._sshd_config()
        env_on = cfg.get("permituserenvironment", ("no",))[0].lower() not in ("no",)
        for u in self.homes():
            fp = f"{u['home']}/.ssh/environment"
            txt = self.read(fp)
            if txt is None:
                continue
            rec("ssh environment", fp, txt.strip())
            hot = re.search(r"\bLD_(PRELOAD|LIBRARY_PATH|AUDIT)\b|^\s*PATH\s*=", txt, re.M)
            self.add("high" if env_on and hot else "medium" if env_on else "low", "persistence",
                     "ssh-environment", f"{fp} sets variables for {u['name']}'s SSH logins"
                     + ("" if env_on else " (inactive: PermitUserEnvironment is off)"),
                     ["T1546", "T1574.006"], "With PermitUserEnvironment, sshd applies these "
                     "variables to every login: LD_PRELOAD or PATH here hijacks the session.",
                     "", {"file": fp, "content": txt[:400], "permituserenvironment": env_on}, fp)
        for k, sev, title, why in (
                ("trustedusercakeys", "high", "sshd trusts user certificates signed by {v}",
                 "Anyone holding that CA key can mint a login certificate for any user: a "
                 "backdoor no authorized_keys review will find."),
                ("authorizedprincipalscommand", "high", "sshd asks {v} which principals may log in",
                 "A program decides who may log in."),
                ("authorizedprincipalsfile", "medium", "sshd AuthorizedPrincipalsFile {v}", ""),
                ("forcecommand", "medium", "sshd ForceCommand {v}",
                 "Every SSH session runs this command first."),
                ("permituserenvironment", "medium", "sshd PermitUserEnvironment {v}",
                 "Users' ~/.ssh/environment and environment= key options are honoured.")):
            if k in cfg and cfg[k][0].lower() not in ("none", "no"):
                v = cfg[k][0]
                rec("sshd " + k, cfg[k][1], v)
                self.add(sev, "persistence", "sshd-trust", title.format(v=v) + f" ({cfg[k][1]})",
                         ["T1098.004", "T1556"], why, "",
                         {"directive": k, "value": v, "file": cfg[k][1]}, k)

        # ---- B. logrotate scripts ------------------------------------------------
        for fp in ["/etc/logrotate.conf"] + ["/etc/logrotate.d/" + f for f in self.ls("/etc/logrotate.d")
                                             if not f.startswith(".") and not f.endswith(("~", ".dpkg-old", ".dpkg-dist"))]:
            txt = self.read(fp)
            if not txt:
                continue
            for kind, body in re.findall(r"^\s*(postrotate|prerotate|firstaction|lastaction|preremove)"
                                         r"\b(.*?)^\s*endscript", txt, re.M | re.S):
                body = body.strip()
                ex = self.describe_exec([l for l in body.splitlines() if l.strip()])
                pk = self.owner(fp)
                mod = bool(pk) and self.conf_modified(fp)
                flags = (["unpackaged"] if not pk else []) + (["modified"] if mod else [])
                rec(f"logrotate {kind}", fp, body, flags)
                s = sus(body)
                ww = [t for t in ex["unpackaged"] if t.startswith(WW_DIRS + ("/home/",))]
                if s or ww or ((not pk or mod) and ex["unpackaged"]):
                    for t in ex["unpackaged"]:
                        self.grab(t, None, f"run by logrotate {kind} ({fp})")
                    self.add("high" if (s or ww) else "medium", "persistence", "logrotate-script",
                             f"logrotate {kind} in {fp} runs " + (s or ", ".join(ex["unpackaged"][:2])),
                             ["T1053.003", "T1546"], "logrotate runs these scripts as root every "
                             "day from cron/systemd - an inconspicuous scheduled-execution point.",
                             "", {"file": fp, "script": body[:600], "exec_targets": ex["targets"],
                                  "package": pk, "modified_from_package": mod}, f"{fp}|{kind}")

        # ---- C. Python startup hooks -------------------------------------------------
        pydirs = set()
        for pat in ("/usr/lib/python3*/site-packages", "/usr/lib/python3/dist-packages",
                    "/usr/local/lib/python3*/site-packages", "/usr/local/lib/python3*/dist-packages",
                    "/usr/lib/python3*", "/usr/local/lib/python3*", "/etc/python3*"):
            pydirs.update(glob.glob(self.p(pat)))
        for u in self.homes():
            pydirs.update(glob.glob(self.p(f"{u['home']}/.local/lib/python3*/site-packages")))
        for d in sorted(pydirs):
            if not os.path.isdir(d):
                continue
            for fn in sorted(os.listdir(d)):
                if not (fn.endswith(".pth") or fn in ("sitecustomize.py", "usercustomize.py")):
                    continue
                full = os.path.join(d, fn)
                path = self.hostpath(full)
                try:
                    with open(full, errors="replace") as fh:
                        txt = fh.read(1 << 20)
                except OSError:
                    continue
                code = txt if fn.endswith(".py") else "\n".join(
                    l for l in txt.splitlines() if l.startswith(("import ", "import\t")))
                if not code.strip():
                    continue                     # plain .pth path entries do not execute
                pk = self.owner(path)
                mod = bool(pk) and self.pkg_modified(path)
                bad = self.PY_BAD.search(code)
                weak = self.PY_WEAK.search(code)
                rec("python startup hook", path, code.strip()[:200],
                    (["unpackaged"] if not pk else []) + (["modified"] if mod else []) +
                    (["suspicious"] if bad else []))
                if pk and not mod:
                    continue                 # dpkg-verified, unchanged since installation
                if mod or bad:
                    sev = "high"
                elif fn.endswith(".py") or (weak and not self.PY_BENIGN_PTH.search(fn)):
                    sev = "medium"
                elif weak:
                    sev = "low"
                else:
                    continue
                hit = bad or weak
                if sev != "low":
                    self.grab(path, None, "python startup hook")
                self.add(sev, "persistence", "python-startup-hook",
                         f"Python startup hook {path} executes code in every Python process"
                         + (" (modified from its package)" if mod else "")
                         + (f" ({hit.group(0)})" if hit else ""), ["T1546.018"],
                         "Executable lines in *.pth files and sitecustomize/usercustomize.py "
                         "run whenever any Python program starts - including root's tools. "
                         "pip packages use this for small path tweaks; code that decodes, "
                         "execs or opens sockets does not belong there.", "",
                         {"file": path, "package": pk, "code": code[:600]}, path)

        # ---- D. git configuration hooks ---------------------------------------------
        gitfiles = ["/etc/gitconfig"] + [f"{u['home']}/{n}" for u in self.homes()
                                         for n in (".gitconfig", ".config/git/config")]
        for fp in gitfiles:
            txt = self.read(fp)
            if not txt:
                continue
            sect = ""
            for line in txt.splitlines():
                s = line.strip()
                m = re.match(r"^\[([^\]]+)\]", s)
                if m:
                    sect = m.group(1).lower().replace('"', "").replace(" ", ".")
                    continue
                if "=" not in s or s.startswith(("#", ";")):
                    continue
                k, v = [x.strip() for x in s.split("=", 1)]
                key = f"{sect}.{k.lower()}"
                runs = key in ("core.fsmonitor", "core.pager", "core.sshcommand", "core.editor",
                               "core.hookspath", "core.askpass", "credential.helper",
                               "sequence.editor", "diff.external") or \
                    (sect == "alias" and v.startswith("!"))
                if not runs or v.lower() in ("true", "false", "", "less", "cat", "vim", "nano", "vi"):
                    continue
                rec("git " + key, fp, v)
                hot = sus(v) or key == "core.fsmonitor" or \
                    (key == "core.hookspath" and v.startswith(WW_DIRS + ("/home/", "~")))
                if hot:
                    self.add("high" if (sus(v) or key == "core.fsmonitor") else "medium",
                             "persistence", "git-config-exec", f"git {key} in {fp} runs: {v[:90]}",
                             ["T1546"], "git runs these commands on routine operations (status, "
                             "log, push). core.fsmonitor in particular executes on every "
                             "'git status' an admin types.", "", {"file": fp, "key": key, "value": v},
                             f"{fp}|{key}")

        # ---- E. authentication plug-ins: NSS, sudo, polkit ---------------------------------
        std_nss = {"files", "dns", "systemd", "compat", "myhostname", "mymachines", "resolve",
                   "sss", "ldap", "winbind", "nis", "nisplus", "db", "extrausers", "wins",
                   "mdns", "mdns4", "mdns6", "mdns_minimal", "mdns4_minimal", "mdns6_minimal",
                   "hesiod", "cache", "altfiles", "usrfiles", "oslogin", "oslogin_cache"}
        for line in (self.read("/etc/nsswitch.conf") or "").splitlines():
            s = line.split("#")[0].strip()
            if ":" not in s:
                continue
            db, srcs = s.split(":", 1)
            for mod in re.findall(r"(?<!\[)\b([a-z][a-z0-9_]*)\b(?![^\[]*\])", srcs):
                lib = self._lib_lookup(f"libnss_{mod}.so.2")
                rec("nss module", "/etc/nsswitch.conf", f"{db.strip()}: {mod} -> {lib or '?'}")
                if lib and not self.owner(lib):
                    sha = self.grab(lib, None, "NSS module")
                    self.add("critical", "persistence", "nss-module-unpackaged",
                             f"nsswitch.conf loads unpackaged NSS module {lib} ({db.strip()})",
                             ["T1556"], "NSS modules are loaded into every process that looks up "
                             "a user or host - including sshd and login. An unpackaged one can "
                             "invent users, hide them, or log credentials.", "",
                             {"database": db.strip(), "module": mod, "library": lib, "sha256": sha},
                             lib)
                elif not lib and mod not in std_nss:
                    rec("nss module", "/etc/nsswitch.conf", f"{mod}: library not found", ["unknown"])
        for line in (self.read("/etc/sudo.conf") or "").splitlines():
            m = re.match(r"^\s*Plugin\s+(\S+)\s+(\S+)", line)
            if not m:
                continue
            path = m.group(2)
            if not path.startswith("/"):
                path = next((f"{d}/{path}" for d in ("/usr/libexec/sudo", "/usr/lib/sudo",
                                                     "/usr/lib/x86_64-linux-gnu/sudo")
                             if os.path.exists(self.p(f"{d}/{path}"))), path)
            rec("sudo plugin", "/etc/sudo.conf", f"{m.group(1)} {path}")
            if path.startswith("/") and os.path.exists(self.p(path)) and not self.owner(path):
                sha = self.grab(path, None, "sudo plugin")
                self.add("critical", "persistence", "sudo-plugin-unpackaged",
                         f"sudo loads unpackaged plugin {path}", ["T1548.003", "T1556"],
                         "A sudo plugin sees every sudo password and can approve any command.",
                         "", {"plugin": m.group(1), "path": path, "sha256": sha}, path)
        for d in ("/etc/polkit-1/rules.d", "/usr/share/polkit-1/rules.d"):
            for f in self.ls(d):
                fp = f"{d}/{f}"
                txt = self.read(fp) or ""
                if "polkit.Result.YES" in txt and not self.owner(fp):
                    rec("polkit rule", fp, "returns polkit.Result.YES", ["unpackaged"])
                    self.add("high", "persistence", "polkit-rule",
                             f"Unpackaged polkit rule {fp} grants actions without authentication",
                             ["T1548"], "polkit rules returning YES let a user run privileged "
                             "actions (start services, install packages...) without a password.",
                             "", {"file": fp, "content": txt[:600]}, fp)
        for fp in glob.glob(self.p("/etc/polkit-1/localauthority/*/*.pkla")) + \
                glob.glob(self.p("/var/lib/polkit-1/localauthority/*/*.pkla")):
            hp = self.hostpath(fp)
            txt = self.read(hp, 1 << 20) or ""
            if re.search(r"^\s*Result(Any|Active|Inactive)\s*=\s*yes", txt, re.M | re.I):
                rec("polkit pkla", hp, "Result*=yes", [] if self.owner(hp) else ["unpackaged"])
                if not self.owner(hp):
                    self.add("high", "persistence", "polkit-rule",
                             f"polkit local authority {hp} grants actions without authentication",
                             ["T1548"], "", "", {"file": hp, "content": txt[:600]}, hp)

        # ---- F. web-server modules and PHP auto_prepend ----------------------------------
        webconf = []
        for pat in ("/etc/apache2/apache2.conf", "/etc/apache2/mods-enabled/*.load",
                    "/etc/apache2/mods-enabled/*.conf", "/etc/apache2/conf-enabled/*.conf",
                    "/etc/apache2/sites-enabled/*", "/etc/httpd/conf/httpd.conf",
                    "/etc/httpd/conf.modules.d/*.conf", "/etc/nginx/nginx.conf",
                    "/etc/nginx/modules-enabled/*.conf", "/etc/nginx/conf.d/*.conf",
                    "/etc/nginx/sites-enabled/*"):
            webconf += [self.hostpath(x) for x in glob.glob(self.p(pat))]
        for fp in webconf:
            for m in re.finditer(r"^\s*(LoadModule\s+\S+|load_module)\s+\"?([^\s\";]+)", self.read(fp) or "",
                                 re.M | re.I):
                path = m.group(2)
                if not path.startswith("/"):
                    path = next((f"{d}/{path}" for d in ("/usr/lib/apache2", "/etc/apache2",
                                                         "/etc/httpd", "/usr/share/nginx",
                                                         "/usr/lib/nginx", "/etc/nginx")
                                 if os.path.exists(self.p(f"{d}/{path}"))), path)
                rec("web server module", fp, f"{m.group(1)} {path}")
                if path.startswith("/") and os.path.exists(self.p(path)) and not self.owner(path):
                    sha = self.grab(path, None, "web server module")
                    self.add("critical", "persistence", "webserver-module-unpackaged",
                             f"Web server loads unpackaged module {path} ({fp})", ["T1505"],
                             "A malicious Apache/nginx module sees every request and response: "
                             "a backdoor that leaves no file in the web root.", "",
                             {"config": fp, "module": path, "sha256": sha}, path)
        phpfiles = []
        for pat in ("/etc/php/*/*/php.ini", "/etc/php/*/*/conf.d/*.ini", "/etc/php/*/mods-available/*.ini",
                    "/etc/php.ini", "/etc/php.d/*.ini", "/usr/local/etc/php/*.ini",
                    "/usr/local/etc/php/conf.d/*.ini"):
            phpfiles += [self.hostpath(x) for x in glob.glob(self.p(pat))]
        for root_ in ("/var/www", "/srv", "/usr/share/nginx/html"):
            base = self.p(root_)
            for dp, dn, fn in os.walk(base):
                if dp[len(base):].count("/") > 6:
                    dn[:] = []
                for f in fn:
                    if f in (".user.ini", ".htaccess"):
                        phpfiles.append(self.hostpath(os.path.join(dp, f)))
        for fp in phpfiles:
            for m in re.finditer(r"^\s*(?:php_value\s+)?(auto_(?:prepend|append)_file)\s*=?\s*\"?([^\s\";]*)",
                                 self.read(fp) or "", re.M | re.I):
                v = m.group(2)
                if not v or v.lower() == "none":
                    continue
                rec("php " + m.group(1), fp, v)
                if v.startswith("/"):
                    self.grab(v, None, "PHP auto_prepend/append file")
                self.add("high", "persistence", "php-auto-prepend",
                         f"PHP {m.group(1)} = {v} ({fp})", ["T1505.003"],
                         "auto_prepend_file makes PHP run that file before every script: a "
                         "web-shell persistence that survives deleting the shell from the "
                         "web root.", "", {"config": fp, "directive": m.group(1), "file": v},
                         f"{fp}|{m.group(1)}")

        # ---- G. unpackaged shared libraries in system library directories -----------------
        if self.owned():
            libdirs = set()
            for pat in ("/usr/lib/*-linux-gnu*", "/lib/*-linux-gnu*", "/usr/lib", "/usr/lib64", "/lib64"):
                libdirs.update(os.path.realpath(x) for x in glob.glob(self.p(pat)) if os.path.isdir(x))
            for d in sorted(libdirs):
                for e in os.scandir(d):
                    if not re.search(r"\.so(\.[\d.]+)?$", e.name):
                        continue
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    path = self.hostpath(e.path)
                    if self.owner(path):
                        continue
                    recent = self.is_recent(st)
                    rec("unpackaged library", path, f"{st.st_size} bytes, changed {iso(st.st_ctime)}",
                        ["recent"] if recent else [])
                    sha = self.grab(path, None, "unpackaged system library") if recent else None
                    self.add("high" if recent else "medium", "persistence", "lib-unpackaged",
                             f"Unpackaged shared library in a system lib dir: {path}",
                             ["T1574.006"], "Rootkit and hijack libraries (libprocesshider, "
                             "Symbiote, Ebury helpers) are dropped next to real libraries so "
                             "ld.so.preload or a modified binary can load them.", "",
                             {"file": path, "size": st.st_size, "changed": iso(st.st_ctime),
                              "sha256": sha}, path)

        # ---- H. PATH interception: /usr/local shadows system binaries ---------------------
        sensitive = {"sudo", "su", "ssh", "sshd", "scp", "ps", "ls", "netstat", "ss", "top",
                     "login", "passwd", "bash", "sh", "ip", "lsof", "find", "crontab", "systemctl",
                     "kill", "w", "who", "last", "id", "pkill", "pgrep", "dpkg", "apt", "apt-get",
                     "curl", "wget", "chattr", "lsattr", "journalctl", "useradd", "usermod"}
        for d in ("/usr/local/sbin", "/usr/local/bin"):
            for f in self.ls(d):
                fp = f"{d}/{f}"
                st = self.lstat(fp)
                if not st or stat.S_ISDIR(st.st_mode):
                    continue
                sysbin = next((f"{s}/{f}" for s in ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
                               if self.owner(f"{s}/{f}")), None)
                if not sysbin:
                    continue
                if stat.S_ISLNK(st.st_mode) and os.path.realpath(self.p(fp)) == \
                        os.path.realpath(self.p(sysbin)):
                    continue
                rec("PATH shadowing", fp, f"shadows {sysbin}", ["shadow"])
                sha = self.grab(fp, None, "binary shadowing a system command")
                self.add("high" if f in sensitive else "medium", "persistence", "path-shadowing",
                         f"{fp} shadows the system command {sysbin}", ["T1574.007"],
                         "/usr/local/bin comes before /usr/bin in PATH, so this file runs "
                         "instead of the real one whenever anyone types the bare name. Admins "
                         "sometimes install newer builds there; a fake sudo/ps/ssh is a classic "
                         "credential stealer or rootkit helper.", "",
                         {"file": fp, "shadows": sysbin, "sha256": sha}, fp)

        # ---- I. boot: kernel command line, initramfs, inittab -------------------------------
        cmdlines = []
        if self.live:
            cmdlines.append(("/proc/cmdline", self.read("/proc/cmdline") or ""))
        for line in (self.read("/etc/default/grub") or "").splitlines():
            if line.startswith("GRUB_CMDLINE"):
                cmdlines.append(("/etc/default/grub", line))
        for line in (self.read("/boot/grub/grub.cfg") or self.read("/boot/grub2/grub.cfg") or "").splitlines():
            if re.match(r"^\s*linux(efi)?\s", line):
                cmdlines.append(("/boot/grub/grub.cfg", line))
        for src, line in cmdlines:
            m = re.search(r"\b(rd)?init=(\S+)", line)
            if m and m.group(2).strip('"') not in ("/sbin/init", "/lib/systemd/systemd",
                                                   "/usr/lib/systemd/systemd", "/init"):
                rec("kernel cmdline", src, line.strip())
                self.add("critical", "persistence", "boot-init-override",
                         f"Kernel command line runs {m.group(1) or ''}init={m.group(2)} ({src})",
                         ["T1037"], "init= replaces PID 1: the attacker's program starts before "
                         "anything else at every boot.", "", {"source": src, "line": line.strip()},
                         f"{src}|{m.group(0)}")
            if "LD_PRELOAD" in line:
                self.add("critical", "persistence", "boot-init-override",
                         f"Kernel command line sets LD_PRELOAD ({src})", ["T1574.006"], "", "",
                         {"source": src, "line": line.strip()}, f"{src}|ld")
        for d in ("/etc/initramfs-tools/hooks", "/etc/initramfs-tools/scripts",
                  "/usr/share/initramfs-tools/hooks", "/usr/lib/dracut/modules.d", "/etc/dracut.conf.d"):
            base = self.p(d)
            for dp, dn, fn in os.walk(base):
                for f in fn:
                    path = self.hostpath(os.path.join(dp, f))
                    if self.owned() and not self.owner(path):
                        rec("initramfs", path, "", ["unpackaged"])
                        self.grab(path, None, "initramfs hook")
                        self.add("high", "persistence", "initramfs-hook",
                                 f"Unpackaged initramfs hook/script {path}", ["T1037"],
                                 "Code baked into the initramfs runs at every boot before the "
                                 "root filesystem is mounted, and survives reinstalling packages.",
                                 "", {"file": path}, path)
        for line in (self.read("/etc/inittab") or "").splitlines():
            if re.match(r"^[^#:]+:[^:]*:(respawn|once|boot|sysinit|wait):", line) and \
                    (sus(line) or "/tmp" in line or "/dev/shm" in line):
                rec("inittab", "/etc/inittab", line)
                self.add("high", "persistence", "inittab", f"Suspicious inittab entry: {line[:90]}",
                         ["T1037"], "", "", {"line": line}, line)

        # ---- J. systemd extras -------------------------------------------------------------
        for u in self.ls("/var/lib/systemd/linger"):
            has_units = any(os.path.isdir(self.p(f"{x['home']}/.config/systemd/user"))
                            for x in self.homes() if x["name"] == u)
            rec("systemd linger", f"/var/lib/systemd/linger/{u}", "user services start at boot")
            self.add("medium" if has_units else "low", "persistence", "systemd-linger",
                     f"User '{u}' has lingering enabled" + (" and per-user units" if has_units else ""),
                     ["T1543.002"], "Lingering starts the user's systemd units at boot without "
                     "a login - user-level persistence that survives reboots.", "",
                     {"user": u}, u)
        for fp in ["/etc/systemd/system.conf", "/etc/systemd/user.conf"] + \
                [f"/etc/systemd/{d}/{f}" for d in ("system.conf.d", "user.conf.d")
                 for f in self.ls(f"/etc/systemd/{d}")]:
            for line in (self.read(fp) or "").splitlines():
                if re.match(r"^\s*(DefaultEnvironment|ManagerEnvironment)\s*=.*\bLD_(PRELOAD|LIBRARY_PATH|AUDIT)", line):
                    rec("systemd environment", fp, line.strip(), ["ld-preload"])
                    self.add("critical", "persistence", "systemd-env-preload",
                             f"{fp} injects {line.strip()[:80]} into every service", ["T1574.006"],
                             "Every unit systemd starts inherits this library.", "",
                             {"file": fp, "line": line.strip()}, fp)

        # ---- K. small schedulers and hooks ------------------------------------------------
        for fp in ["/etc/anacrontab"]:
            for line in (self.read(fp) or "").splitlines():
                f = line.split(None, 3)
                if len(f) == 4 and (f[0][:1].isdigit() or f[0].startswith("@")):
                    ex = self.describe_exec([f[3]])
                    rec("anacron", fp, f[3], ["unpackaged-exec"] if ex["unpackaged"] else [])
                    if sus(f[3]) or ex["unpackaged"]:
                        self.add("high" if sus(f[3]) else "medium", "persistence", "anacron",
                                 f"anacron job '{f[2]}' runs {f[3][:90]}", ["T1053.003"], "", "",
                                 {"file": fp, "job": f[2], "command": f[3],
                                  "exec_targets": ex["targets"]}, f"{fp}|{f[2]}")
        for d in ("/etc/incron.d", "/var/spool/incron"):
            for f in self.ls(d):
                fp = f"{d}/{f}"
                for line in (self.read(fp) or "").splitlines():
                    if line.strip() and not line.startswith("#"):
                        rec("incron", fp, line.strip())
                        self.add("high" if sus(line) else "medium", "persistence", "incron",
                                 f"incron watch in {fp}: {line.strip()[:90]}", ["T1546"],
                                 "incron runs a command whenever a watched file changes - "
                                 "event-triggered persistence that never shows up in cron.",
                                 "", {"file": fp, "entry": line.strip()}, f"{fp}|{line.strip()}")
        for fp in ("/etc/hosts.allow", "/etc/hosts.deny"):
            for line in (self.read(fp) or "").splitlines():
                if re.search(r":\s*(spawn|twist)\s", line) and not line.lstrip().startswith("#"):
                    rec("tcp wrappers", fp, line.strip())
                    self.add("high", "persistence", "tcpwrappers-spawn",
                             f"{fp} runs a command on connections: {line.strip()[:90]}",
                             ["T1546"], "tcp-wrappers spawn/twist executes a shell command for "
                             "matching inbound connections.", "", {"file": fp, "line": line.strip()},
                             f"{fp}|{line.strip()}")
        for f in self.ls("/etc/dpkg/dpkg.cfg.d"):
            fp = f"/etc/dpkg/dpkg.cfg.d/{f}"
            txt = self.read(fp) or ""
            hooks = re.findall(r"^\s*(?:pre|post)-invoke\s*=?\s*\"?(.+?)\"?\s*$", txt, re.M)
            if hooks:
                pk = self.owner(fp)
                rec("dpkg hook", fp, hooks[0], [] if pk else ["unpackaged"])
                if not pk or any(sus(h) for h in hooks):
                    self.add("high", "persistence", "dpkg-hook",
                             f"dpkg hook in {fp} runs: {hooks[0][:90]}", ["T1546"],
                             "dpkg runs pre/post-invoke commands as root around every package "
                             "operation.", "", {"file": fp, "hooks": hooks}, fp)
        bad_rc = re.compile(r"\bLD_PRELOAD\s*=|\bPROMPT_COMMAND\s*=|^\s*alias\s+(sudo|su|ssh|passwd)=|"
                            r"\btrap\s+.+\s+DEBUG\b", re.M)
        for d in ("/etc/skel", "/etc/bash_completion.d", "/usr/share/bash-completion/completions"):
            base = self.p(d)
            for dp, dn, fn in os.walk(base):
                for f in fn:
                    path = self.hostpath(os.path.join(dp, f))
                    pk = self.owner(path)
                    if pk and d != "/etc/skel":
                        continue
                    txt = self.read(path, 1 << 20) or ""
                    hit = sus(txt) or (bad_rc.search(txt).group(0) if bad_rc.search(txt) else None)
                    if hit:
                        rec("shell init (template)", path, hit, ["suspicious"])
                        self.add("high", "persistence", "skel-or-completion",
                                 f"Suspicious content in {path}: {hit[:60]}", ["T1546.004"],
                                 "/etc/skel files are copied into every NEW account, and "
                                 "bash-completion scripts are sourced by every interactive shell.",
                                 "", {"file": path, "match": hit, "package": pk}, path)
                    elif not pk and d == "/etc/bash_completion.d" and self.is_recent(self.lstat(path)):
                        rec("bash completion", path, "new unpackaged", ["unpackaged"])
                        self.add("medium", "persistence", "skel-or-completion",
                                 f"New unpackaged bash-completion script {path}", ["T1546.004"],
                                 "", "", {"file": path}, path)
        self.table("persistence_more", "Other persistence locations", "persistence",
                   ["kind", "path", "package", "detail", "flags"], rows, key=[0, 1, 3])

    # ------------------------------------------------------------ containers
    def c_containers(self):
        rows = []
        base = self.p("/var/lib/docker/containers")
        for cid in (os.listdir(base) if os.path.isdir(base) else []):
            try:
                with open(os.path.join(base, cid, "config.v2.json")) as fh:
                    cfg = json.load(fh)
            except (OSError, ValueError):
                continue
            try:
                with open(os.path.join(base, cid, "hostconfig.json")) as fh:
                    hc = json.load(fh)
            except (OSError, ValueError):
                hc = {}
            c = cfg.get("Config") or {}
            name = (cfg.get("Name") or cid[:12]).lstrip("/")
            restart = (hc.get("RestartPolicy") or {}).get("Name") or "no"
            priv = bool(hc.get("Privileged"))
            mounts = list(hc.get("Binds") or []) + [
                f"{m.get('Source')}:{m.get('Target')}" for m in (cfg.get("MountPoints") or {}).values()
                if m.get("Source")]
            danger = [m for m in mounts if re.match(r"^(/|/etc|/root|/home|/boot|/var/run/docker\.sock|"
                                                     r"/run/docker\.sock|/proc|/sys)(:|$)", m)]
            hostns = [k for k in ("PidMode", "NetworkMode", "IpcMode", "UTSMode")
                      if (hc.get(k) or "") == "host"]
            caps = hc.get("CapAdd") or []
            running = bool((cfg.get("State") or {}).get("Running"))
            cmd = " ".join((c.get("Entrypoint") or []) + (c.get("Cmd") or []))
            flags = (["privileged"] if priv else []) + (["host-mounts"] if danger else []) + \
                [f"host-{k[:-4].lower()}" for k in hostns] + (["autostart"] if restart in
                                                              ("always", "unless-stopped") else [])
            rows.append([name, c.get("Image") or "", "running" if running else "stopped", restart,
                         "yes" if priv else "", " ".join(danger)[:200], " ".join(hostns),
                         " ".join(caps), cmd[:200], cid[:12], flags])
            ev = {"container": name, "id": cid[:12], "image": c.get("Image"), "command": cmd,
                  "restart": restart, "privileged": priv, "host_mounts": danger,
                  "host_namespaces": hostns, "cap_add": caps, "running": running}
            escape = priv or danger or "SYS_ADMIN" in caps or "PidMode" in hostns
            if escape and restart in ("always", "unless-stopped"):
                self.add("high", "persistence", "container-escape-autostart",
                         f"Container {name} ({c.get('Image')}) auto-starts with host access "
                         f"({', '.join(flags)})", ["T1543.005", "T1611"],
                         "A privileged container, or one with the host filesystem or Docker "
                         "socket mounted, is root on the host. With restart=always it comes "
                         "back after every reboot - a persistence trick that never touches "
                         "the host's cron or systemd.", "Inspect the image and its command; "
                         "compare against what the team deployed.", ev, cid)
            elif escape:
                self.add("medium", "persistence", "container-host-access",
                         f"Container {name} ({c.get('Image')}) has host access ({', '.join(flags)})",
                         ["T1611"], "", "", ev, cid)
        if rows:
            self.table("containers", "Docker containers", "persistence",
                       ["name", "image", "state", "restart", "privileged", "host mounts",
                        "host namespaces", "cap add", "command", "id", "flags"], rows,
                       key=[0, 1, 3, 4, 5, 8])
        for f in self.ls("/etc/kubernetes/manifests"):
            fp = f"/etc/kubernetes/manifests/{f}"
            st = self.lstat(fp)
            if self.is_recent(st):
                self.add("medium", "persistence", "k8s-static-pod",
                         f"Kubernetes static pod manifest changed recently: {fp}",
                         ["T1543.005"], "kubelet runs static pods from this directory on its own, "
                         "outside the API server's view.", "", {"file": fp,
                                                                 "modified": iso(st.st_mtime)}, fp)

    # ------------------------------------------------------ immutable files
    def c_immutable(self):
        """chattr +i / +a on persistence files stops admins from removing them."""
        def flags_of(fp):
            try:
                fd = os.open(fp, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            except OSError:
                return 0
            try:
                buf = array.array("l", [0])
                fcntl.ioctl(fd, 0x80086601, buf, True)        # FS_IOC_GETFLAGS
                return buf[0]
            except OSError:
                return 0
            finally:
                os.close(fd)
        sensitive = re.compile(r"authorized_keys|/etc/(passwd|shadow|group|sudoers|ld\.so\.preload|"
                               r"crontab|rc\.local|profile|bash\.bashrc|pam\.d/)|/cron|systemd/system/|"
                               r"/\.bashrc$|/\.profile$|\.service$|\.timer$")
        targets = []
        for d in ("/etc", "/var/spool/cron", "/usr/bin", "/usr/sbin", "/usr/local/bin",
                  "/usr/local/sbin", "/root", "/usr/lib/systemd/system", "/lib/systemd/system"):
            base = self.p(d)
            for dp, dn, fn in os.walk(base):
                if dp[len(base):].count("/") > 3:
                    dn[:] = []
                targets += [os.path.join(dp, f) for f in fn]
        for u in self.homes():
            targets += glob.glob(self.p(f"{u['home']}/.ssh/*")) + \
                [self.p(f"{u['home']}/{n}") for n in (".bashrc", ".profile", ".bash_profile")]
        rows, seen = [], set()
        for fp in targets:
            if fp in seen:
                continue
            seen.add(fp)
            fl = flags_of(fp)
            if not fl & 0x30:
                continue
            path = self.hostpath(fp)
            kind = "immutable" if fl & 0x10 else "append-only"
            rows.append([path, kind, self.owner(path) or "", ["locked"]])
            sev = "high" if sensitive.search(path) else ("low" if path.endswith("resolv.conf")
                                                         else "medium")
            self.add(sev, "persistence", "immutable-file", f"{path} is {kind} (chattr +"
                     f"{'i' if fl & 0x10 else 'a'})", ["T1222.002"],
                     "Attackers lock their cron jobs, keys and binaries with chattr so that "
                     "rm, editors and package upgrades fail - and so cleanup silently leaves "
                     "them in place.", "Remove the flag with chattr -i before cleanup; ask "
                     "who set it.", {"file": path, "attribute": kind}, path)
        self.table("immutable", "Immutable / append-only files", "persistence",
                   ["file", "attribute", "package", "flags"], rows, key=[0, 1])

    # --------------------------------------------------------- shell init
    def c_shell_init(self):
        sysf = ["/etc/profile", "/etc/bash.bashrc", "/etc/environment", "/etc/zsh/zshrc",
                "/etc/zsh/zprofile", "/etc/zsh/zshenv", "/etc/bash.bash_logout"]
        sysf += ["/etc/profile.d/" + f for f in self.ls("/etc/profile.d")]
        userf = (".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_logout",
                 ".zshrc", ".zprofile", ".zshenv", ".zlogin")
        files = [(f, "system") for f in sysf]
        for u in self.homes():
            files += [(f"{u['home']}/{f}", u["name"]) for f in userf]
        bad = re.compile(r"\bLD_PRELOAD\s*=|\bPROMPT_COMMAND\s*=|^\s*alias\s+(sudo|su|ssh|scp|ps|"
                         r"netstat|ss|lsof|passwd)=|\btrap\s+.+\s+DEBUG\b|"
                         r"HISTFILE\s*=\s*/dev/null|HISTSIZE\s*=\s*0\b|unset\s+HISTFILE", re.M)
        rows = []
        for fp, who in files:
            txt = self.read(fp, 1 << 20)
            if txt is None:
                continue
            st = self.lstat(fp)
            pk = self.owner(fp)
            flags = []
            hits = [l.strip() for l in txt.splitlines()
                    if l.strip() and not l.strip().startswith("#") and
                    (SUSPECT_CMD.search(l) or bad.search(l) or
                     (WW_PATH.search(l) and re.search(r"(^|[;&|]\s*)(\.|source|exec|/)", l.strip())))]
            if hits:
                flags.append("suspicious")
                hist = any(re.search(r"HIST|history", h) for h in hits)
                self.add("high", "persistence", "shell-init",
                         f"Suspicious line(s) in {fp}", ["T1070.003"] if hist else ["T1546.004"],
                         "Shell start-up files run for every interactive login. Attackers add "
                         "callbacks, LD_PRELOAD, credential-stealing aliases (sudo/ssh) or "
                         "history suppression here.", "",
                         {"file": fp, "owner": who, "lines": hits[:12]}, fp)
            if fp.startswith("/etc/profile.d/") and self.owned() and not pk:
                flags.append("unpackaged")
                if self.is_recent(st):
                    self.add("medium", "persistence", "profile-d-recent",
                             f"New unpackaged login script {fp}", ["T1546.004"], "", "",
                             {"file": fp, "modified": iso(st.st_mtime)}, fp)
            if self.is_recent(st):
                flags.append("recent")
            rows.append([fp, who, pk or "", iso(st.st_mtime) if st else "", flags])
        self.table("shell_init", "Shell start-up files", "persistence",
                   ["file", "owner", "package", "modified", "flags"], rows, key=[0])

    # ------------------------------------------------------- shell history
    def c_history(self):
        names = (".bash_history", ".zsh_history", ".ash_history", ".sh_history",
                 ".python_history", ".mysql_history", ".psql_history")
        note = re.compile(r"\b(wget|curl)\s+\S*https?://|\bchmod\s+\+x\b|\buseradd\b|\busermod\b|"
                          r"\bpasswd\b|ssh-keygen|authorized_keys|\bcrontab\b|\binsmod\b|\bnohup\b|"
                          r"\biptables\s+-F|\bsetenforce\s+0|systemctl\s+(stop|disable)\s+\S*"
                          r"(audit|wazuh|ossec|falcon|osquery|sysmon|clamav|imunify)|/dev/shm|"
                          r"\bscp\b|\brsync\b.*@|\bnmap\b|\bmasscan\b|\bhydra\b|ld\.so\.preload")
        rows = []
        for u in self.homes():
            for n in names:
                fp = f"{u['home']}/{n}"
                st = self.lstat(fp)
                if st is None:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    tgt = readlink(self.p(fp)) or ""
                    if tgt == "/dev/null":
                        self.add("high", "logs", "history-devnull",
                                 f"{fp} is a symlink to /dev/null", ["T1070.003"],
                                 "Shell history is being deliberately discarded.", "",
                                 {"file": fp, "user": u["name"]}, fp)
                    continue
                txt = self.read(fp, 16 << 20) or ""
                lines = txt.splitlines()
                if not lines and u.get("uid") == 0 and n == ".bash_history":
                    rows.append([u["name"], fp, "", "(empty)", []])
                hits = []
                for i, l in enumerate(lines):
                    l2 = re.sub(r"^: \d+:\d+;", "", l).strip()   # zsh extended format
                    if not l2 or l2.startswith("#"):
                        continue
                    if SUSPECT_CMD.search(l2):
                        rows.append([u["name"], fp, i + 1, l2[:220], ["suspicious"]])
                        hits.append(f"{i + 1}: {l2[:200]}")
                    elif note.search(l2):
                        rows.append([u["name"], fp, i + 1, l2[:220], []])
                if hits:
                    self.add("high", "logs", "history-suspicious",
                             f"{len(hits)} suspicious command(s) in {u['name']}'s {n}",
                             ["T1059.004"], "Matches download-and-execute, reverse-shell, "
                             "decoding, miner or anti-forensics patterns. On a lab or analyst "
                             "box these may be your own commands - check the timeline.",
                             "", {"file": fp, "lines": hits[:40], "total": len(hits)},
                             f"{fp}|" + hashlib.sha1("\n".join(hits).encode()).hexdigest())
        self.table("history", "Shell history highlights", "logs",
                   ["user", "file", "line", "command", "flags"], rows[-1500:], key=[0, 1, 3])

    # -------------------------------------------------------------- logins
    def _utmp(self, path):
        out = []
        try:
            with open(self.p(path), "rb") as fh:
                data = fh.read(64 << 20)
        except OSError:
            return None
        for off in range(0, len(data) - UT.size + 1, UT.size):
            f = UT.unpack_from(data, off)
            typ = f[0]
            out.append({"type": typ, "pid": f[1],
                        "line": f[2].split(b"\0")[0].decode("utf-8", "replace"),
                        "user": f[4].split(b"\0")[0].decode("utf-8", "replace"),
                        "host": f[5].split(b"\0")[0].decode("utf-8", "replace"),
                        "ts": f[9]})
        return out

    def c_logins(self):
        fails, fail_users = Counter(), defaultdict(set)
        btmp = []
        for p_ in ("/var/log/btmp", "/var/log/btmp.1"):
            btmp += self._utmp(p_) or []
        for r in btmp:
            if r["host"]:
                fails[r["host"]] += 1
                fail_users[r["host"]].add(r["user"])
        acc = {}                                     # (user, host, method) -> rec
        events = []
        logs = sorted(glob.glob(self.p("/var/log/auth.log*")) + glob.glob(self.p("/var/log/secure*")))
        acc_re = re.compile(r"sshd\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port")
        fail_re = re.compile(r"sshd\[\d+\]: (?:Failed \S+ for (?:invalid user )?(\S+)|"
                             r"Invalid user (\S*)) from (\S+)")
        ev_re = re.compile(r"(useradd\[\d+\]: new user: name=[^,]+|usermod\[\d+\]: add '[^']+' "
                           r"to (?:shadow )?group '[^']+'|passwd\[\d+\]: .*password changed for \S+|"
                           r"groupadd\[\d+\]: new group: name=[^,]+|userdel\[\d+\]: delete user '[^']+')")
        for lf in logs:
            try:
                opener = gzip.open if lf.endswith(".gz") else open
                with opener(lf, "rt", errors="replace") as fh:
                    for line in fh:
                        if "sshd[" in line:
                            m = acc_re.search(line)
                            if m:
                                k = (m.group(2), m.group(3), m.group(1))
                                ts_ = line[:32].split(" ")[0] if line[:4].isdigit() else line[:15]
                                a = acc.setdefault(k, {"n": 0, "first": ts_, "last": ts_})
                                a["n"] += 1
                                a["last"] = ts_
                                continue
                            m = fail_re.search(line)
                            if m:
                                fails[m.group(3)] += 1
                                fail_users[m.group(3)].add(m.group(1) or m.group(2) or "?")
                                continue
                        m = ev_re.search(line)
                        if m:
                            events.append([self.hostpath(lf), line.strip()[:200]])
            except (OSError, EOFError, zlib.error):
                pass
        if not logs:
            self.errors.append({"check": "logins", "error": "no /var/log/auth.log* - journald-only "
                                "host? run: journalctl -u ssh -u sshd --since -30d"})
        wtmp = self._utmp("/var/log/wtmp")
        logins = [r for r in (wtmp or []) if r["type"] == 7]
        for r in logins:
            if r["host"]:
                k = (r["user"], r["host"], "wtmp")
                a = acc.setdefault(k, {"n": 0, "first": iso(r["ts"]), "last": iso(r["ts"])})
                a["n"] += 1
                a["last"] = iso(r["ts"])
        svc = {u["name"] for u in self.users if 0 < u["uid"] < 1000}
        rows = []
        for (user, host, method), a in sorted(acc.items(), key=lambda x: -x[1]["n"]):
            flags = []
            ext = not is_private(host) and re.match(r"^[0-9a-fA-F.:]+$", host or "")
            if ext:
                flags.append("external")
            nf = fails.get(host, 0)
            ev = {"user": user, "from": host, "method": method, "count": a["n"],
                  "first": a["first"], "last": a["last"], "failures_from_same_source": nf}
            if nf >= 20:
                flags.append("after-bruteforce")
                self.add("high", "accounts", "bruteforce-success",
                         f"'{user}' logged in from {host} which also produced {nf} failed logins",
                         ["T1110", "T1078.003"], "A successful login from a source that was "
                         "brute-forcing is the classic SSH compromise.",
                         "Check what that session did (history, processes started then).",
                         ev, f"{user}|{host}")
            if user in svc:
                flags.append("service-account")
                self.add("high", "accounts", "service-account-login",
                         f"Service account '{user}' logged in from {host}", ["T1078.003"], "",
                         "", ev, f"{user}|{host}")
            if user == "root" and method == "password" and ext:
                self.add("medium", "accounts", "root-password-login",
                         f"root logged in with a password from external {host}",
                         ["T1021.004"], "", "", ev, f"root|{host}")
            rows.append([user, host, method, a["n"], a["first"], a["last"], nf, flags])
        self.table("logins", "Successful logins (wtmp + auth.log)", "accounts",
                   ["user", "from", "method", "count", "first", "last", "failures from source",
                    "flags"], rows, key=[0, 1, 2])
        self.table("failed_logins", "Failed login sources (btmp + auth.log)", "accounts",
                   ["source", "failures", "users tried"],
                   [[h, n, " ".join(sorted(fail_users[h]))[:160]] for h, n in fails.most_common(100)],
                   key=[0])
        if events:
            self.table("account_events", "Account changes recorded in auth logs", "accounts",
                       ["log", "event"], events[-300:], key=[1])
            for lf, line in events:
                if "new user" in line:
                    name = re.search(r"name=([^,]+)", line).group(1)
                    um = re.search(r"UID=(\d+)", line)
                    uid_ = int(um.group(1)) if um else -1
                    self.add("high" if uid_ == 0 else "low" if 0 < uid_ < 1000 else "medium",
                             "accounts", "useradd-event",
                             f"Account '{name}' was created (auth log)", ["T1136.001"], "", "",
                             {"log": lf, "line": line}, f"useradd|{name}")
                elif re.search(r"to (?:shadow )?group '(sudo|root|wheel|admin|docker|lxd|shadow)'", line):
                    self.add("high", "accounts", "privileged-group-add",
                             f"User added to a privileged group: {line.split(': ', 1)[-1][:90]}",
                             ["T1078.003"], "", "", {"log": lf, "line": line}, line[-80:])
        self.hostinfo["wtmp_records"] = len(wtmp) if wtmp is not None else None
        self.fail_counts = fails
        self.wtmp = wtmp or []
        self.hostinfo["auth_logs"] = len(logs)

    # ------------------------------------------------------------ sessions
    def _peer(self, pids):
        for c in getattr(self, "conn_list", []):
            if c.get("pid") in pids and c.get("state") == "ESTABLISHED":
                return c.get("raddr")
        return None

    def c_sessions(self):
        """Who is logged in now (utmp + logind + sshd processes, cross-checked) and
        how long every session lasted (wtmp login/logout pairs, like `last`)."""
        now = time.time()
        fails = getattr(self, "fail_counts", Counter())
        svc = {u["name"] for u in self.users if 0 < u["uid"] < 1000}

        # ---- history: pair USER_PROCESS (7) with DEAD_PROCESS (8) on the same line
        hist, open_ = [], {}
        for r in getattr(self, "wtmp", []):
            if r["type"] == 7:
                if r["line"] in open_:
                    s = open_.pop(r["line"])
                    hist.append(dict(s, end=None, how="no logout record"))
                open_[r["line"]] = {"user": r["user"], "line": r["line"], "host": r["host"],
                                    "start": r["ts"]}
            elif r["type"] == 8 and r["line"] in open_:
                hist.append(dict(open_.pop(r["line"]), end=r["ts"], how="logout"))
            elif r["type"] == 2 or (r["type"] == 1 and r["user"] == "shutdown"):
                for s in open_.values():
                    hist.append(dict(s, end=r["ts"], how="reboot / shutdown"))
                open_.clear()
        for s in open_.values():
            hist.append(dict(s, end=None, how="open (no logout yet)"))
        hist.sort(key=lambda s: s["start"], reverse=True)
        hrows = []
        for s in hist[:500]:
            flags = []
            if s["host"] and not is_private(s["host"]) and re.match(r"^[0-9a-fA-F.:]+$", s["host"]):
                flags.append("external")
            if s["user"] in svc:
                flags.append("service-account")
            length = (s["end"] - s["start"]) if s["end"] else None
            hrows.append([s["user"], s["line"], s["host"] or "local", iso(s["start"]),
                          iso(s["end"]) if s["end"] else "", human_span(length) if length is not None
                          else "", s["how"], flags])
        self.table("session_history", "Session history (wtmp: login, logout, duration)",
                   "accounts", ["user", "tty", "from", "login", "logout", "duration",
                                "ended by", "flags"], hrows, key=[0, 1, 2, 3])
        if not self.live:
            return

        # ---- current sessions --------------------------------------------------
        cur = {}
        for r in (self._utmp("/run/utmp") or self._utmp("/var/run/utmp") or []):
            if r["type"] == 7 and os.path.exists(f"/proc/{r['pid']}"):   # drop stale entries
                cur[("tty", r["line"])] = {"user": r["user"], "tty": r["line"],
                                           "from": r["host"] or "local", "start": r["ts"],
                                           "leader": r["pid"], "src": {"utmp"}}
        for sid in self.ls("/run/systemd/sessions"):
            if "." in sid:
                continue
            kv = dict(l.split("=", 1) for l in (self.read(f"/run/systemd/sessions/{sid}") or "")
                      .splitlines() if "=" in l)
            try:
                leader = int(kv.get("LEADER") or 0)
            except ValueError:
                leader = 0
            if not leader or not os.path.exists(f"/proc/{leader}"):
                continue
            tty = kv.get("TTY") or ""
            rec = cur.get(("tty", tty)) if tty else None
            rec = rec or next((c for c in cur.values() if c["leader"] == leader), None)
            if rec:
                rec["src"].add("logind")
                rec["service"] = kv.get("SERVICE")
                continue
            cur[("tty", tty) if tty else ("leader", leader)] = {
                "user": kv.get("USER", "?"), "tty": tty or "notty",
                "from": kv.get("REMOTE_HOST") or "local",
                "start": int(kv.get("REALTIME") or 0) / 1e6 or self.procs.get(leader, {}).get("start", now),
                "leader": leader, "src": {"logind"}, "service": kv.get("SERVICE")}
        sshd_re = re.compile(r"^sshd(?:-session)?: ([^\s@\[]+)@(\S+)")
        for pid, pr in self.procs.items():
            m = sshd_re.match(pr.get("cmdline") or "")
            if not m:
                continue
            user, tty = m.groups()
            peer = self._peer({pid, pr["ppid"]})
            key = ("tty", tty) if tty != "notty" else None
            rec = cur.get(key) if key else None
            rec = rec or next((c for c in cur.values()
                               if c["leader"] in (pid, pr["ppid"])), None)
            if rec:
                rec["src"].add("sshd")
                rec["sshd_pid"] = pid
                if peer and rec["from"] in ("local", "?"):
                    rec["from"] = peer
                continue
            par = self.procs.get(pr["ppid"], {})
            cur[key or ("sshd", pid)] = {
                "user": user, "tty": tty, "from": peer or "?",
                "start": par.get("start") if "[priv]" in (par.get("cmdline") or "") else pr["start"],
                "leader": pid, "sshd_pid": pid, "src": {"sshd"}}

        bf = {}
        mine = set()
        p_ = os.getpid()
        while p_ > 1:                                # the analyst's own process chain
            mine.add(p_)
            st = self.read(f"/proc/{p_}/status") or ""
            m = re.search(r"^PPid:\s*(\d+)", st, re.M)
            p_ = int(m.group(1)) if m else 0
        rows = []
        for (kind, _), s in sorted(cur.items(), key=lambda x: x[1]["start"]):
            tty, flags = s["tty"], []
            idle, running = None, []
            if tty and tty != "notty":
                try:
                    st = os.stat(f"/dev/{tty}")
                    idle = now - st.st_atime
                    maj, mnr = os.major(st.st_rdev), os.minor(st.st_rdev)
                    tty_nr = (mnr & 0xff) | (maj << 8) | ((mnr & ~0xff) << 12)
                    on = sorted((p for p in self.procs.values() if p.get("tty") == tty_nr),
                                key=lambda p: p["start"])
                    running = [p["comm"] for p in on]
                except OSError:
                    pass
            else:
                kids = [p for p in self.procs.values() if p["ppid"] == s.get("sshd_pid")]
                running = [p["comm"] for p in kids]
            if s["leader"] in mine or s.get("sshd_pid") in mine:
                flags.append("analyst-session")
            ext = s["from"] not in ("local", "?") and not is_private(s["from"]) and \
                re.match(r"^[0-9a-fA-F.:]+$", s["from"])
            if ext:
                flags.append("external")
            ev = {"user": s["user"], "tty": tty, "from": s["from"], "login": iso(s["start"]),
                  "session_length": human_span(now - s["start"]),
                  "idle": human_span(idle) if idle is not None else "?",
                  "seen_in": sorted(s["src"]), "leader_pid": s["leader"],
                  "running": running[-8:]}
            key = f"{s['user']}|{s['from']}|{tty}"
            if "analyst-session" not in flags:
                if s["user"] in svc:
                    flags.append("service-account")
                    self.add("high", "accounts", "session-service-account",
                             f"Service account '{s['user']}' is logged in now ({tty} from "
                             f"{s['from']})", ["T1078.003"], "System accounts do not log in "
                             "interactively. A live session as www-data/nobody is an attacker "
                             "using a web-shell foothold or a planted key.",
                             "Look at what it is running (evidence) before killing it.", ev, key)
                if fails.get(s["from"], 0) >= 20:
                    flags.append("from-bruteforce-source")
                    bf.setdefault((s["user"], s["from"]), []).append((tty, ev))
                if "sshd" in s["src"] and "utmp" not in s["src"] and tty != "notty":
                    flags.append("no-utmp")
                    self.add("medium", "accounts", "session-no-utmp",
                             f"SSH session {s['user']}@{tty} from {s['from']} has no utmp record",
                             ["T1070.002"], "Interactive SSH sessions are recorded in utmp. A "
                             "live one that is missing was hidden - utmp was edited or "
                             "logging was bypassed - so 'who' and 'w' do not show it.", "",
                             ev, key)
                elif tty == "notty":
                    flags.append("notty")
                    self.add("low", "accounts", "session-notty",
                             f"Non-interactive SSH session by '{s['user']}' from {s['from']} "
                             f"(running: {', '.join(running[-4:]) or '?'})", ["T1021.004"],
                             "ssh host <command>, scp and sftp sessions never appear in "
                             "'who'. Usually automation; confirm it is expected.", "", ev, key)
            rows.append([s["user"], tty, s["from"], iso(s["start"]), human_span(now - s["start"]),
                         human_span(idle) if idle is not None else "", "+".join(sorted(s["src"])),
                         s["leader"], " > ".join(running[-6:]), flags])
        for (user, src), lst in bf.items():          # one finding per user + source
            ttys = ", ".join(t for t, _ in lst)
            self.add("high", "accounts", "session-from-bruteforce-source",
                     f"'{user}' has {len(lst)} session(s) open now from {src} ({ttys}), a source "
                     f"that produced {fails[src]} failed logins", ["T1110", "T1078.003"],
                     "Someone is logged in from an address that was guessing passwords. On an "
                     "admin's own workstation this is usually mistyped passwords; otherwise "
                     "treat the sessions as hostile.", "",
                     dict(lst[0][1], sessions=[e for _, e in lst]), f"{user}|{src}")
        self.hostinfo["sessions_now"] = len(rows)
        self.table("sessions", "Logged in now", "accounts",
                   ["user", "tty", "from", "login", "session length", "idle", "seen in",
                    "leader pid", "running", "flags"], rows, key=[0, 1, 2],
                   note="Cross-checked from utmp, systemd-logind and sshd session processes: a "
                        "session hidden from one source still shows up from the others.")

    # ------------------------------------------------------- log integrity
    def c_logs(self):
        rows = []
        up = self.hostinfo.get("uptime_s") or 0
        for fp in ("/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog", "/var/log/auth.log",
                   "/var/log/syslog", "/var/log/messages", "/var/log/secure", "/var/log/kern.log",
                   "/var/log/audit/audit.log"):
            st = self.lstat(fp)
            if st is None:
                continue
            rows.append([fp, st.st_size, iso(st.st_mtime), oct(st.st_mode & 0o7777)])
            if stat.S_ISLNK(st.st_mode) and readlink(self.p(fp)) == "/dev/null":
                self.add("high", "logs", "log-devnull", f"{fp} is a symlink to /dev/null",
                         ["T1070.002"], "Logging is being thrown away.", "", {"file": fp}, fp)
            elif st.st_size == 0 and fp in ("/var/log/wtmp", "/var/log/lastlog", "/var/log/auth.log",
                                            "/var/log/syslog", "/var/log/secure") \
                    and (not self.live or up > 86400) and not self.hostinfo.get("container"):
                self.add("medium", "logs", "log-empty", f"{fp} is empty", ["T1070.002"],
                         "An empty login/system log on a host that has been up for days usually "
                         "means it was truncated. (A rotation minutes ago is the benign case.)",
                         "", {"file": fp, "modified": iso(st.st_mtime)}, fp)
        self.table("logfiles", "Key log files", "logs", ["file", "size", "modified", "mode"],
                   rows, key=[0])

    # -------------------------------------------------- package integrity
    def c_packages(self):
        if not self.owned():
            return
        mism, missing, checked = [], 0, 0
        for mf in glob.glob(self.p("/var/lib/dpkg/info") + "/*.md5sums"):
            pkg = os.path.basename(mf)[:-8].split(":")[0]
            try:
                fh = open(mf, errors="replace")
            except OSError:
                continue
            with fh:
                for line in fh:
                    md5, _, rel = line.rstrip("\n").partition("  ")
                    if not rel or (not self.deep and not DPKG_CRITICAL.search(rel)):
                        continue
                    path = "/" + rel
                    if path in self._diverted:
                        continue
                    try:
                        st = os.stat(self.p(path))
                        if not stat.S_ISREG(st.st_mode):
                            continue
                        digest = _md5(self.p(path))
                    except FileNotFoundError:
                        missing += 1
                        continue
                    except OSError:
                        continue
                    checked += 1
                    if digest != md5:
                        mism.append((path, pkg, md5, digest, st))
        rows = []
        for path, pkg, want, got, st in mism:
            sha = self.grab(path, None, "dpkg checksum mismatch")
            rows.append([path, pkg, want, got, iso(st.st_mtime), iso(st.st_ctime)])
            self.add("critical", "integrity", "dpkg-mismatch",
                     f"{path} does not match its package ({pkg})", ["T1554"],
                     "The file on disk differs from what dpkg installed. Trojaned sshd, ps, "
                     "ss, sudo or libkeyutils (Ebury) are found exactly this way.",
                     "Compare with a clean copy of the same package version "
                     "(apt-get download " + pkg + ").",
                     {"file": path, "package": pkg, "expected_md5": want, "actual_md5": got,
                      "sha256": sha, "modified": iso(st.st_mtime), "changed": iso(st.st_ctime)},
                     path)
        self.table("dpkg_verify", "Package checksum mismatches", "integrity",
                   ["file", "package", "expected md5", "actual md5", "modified", "changed"], rows,
                   key=[0, 3])
        self.hostinfo["dpkg_files_verified"] = checked
        self.hostinfo["dpkg_files_missing"] = missing
        self.hostinfo["dpkg_scope"] = "all packaged files" if self.deep else \
            "binaries, PAM, sshd helpers, core libraries"

        # modified conffiles (dpkg keeps their original md5 in the status file)
        rel = re.compile(r"^/etc/(pam\.d/|sudoers|ssh/|security/|ld\.so|profile|bash\.bashrc|"
                         r"crontab|cron\.|systemd/|apt/apt\.conf\.d/|update-motd\.d/|init\.d/|"
                         r"rc\.local|environment|udev/|modprobe\.d/|modules|nsswitch\.conf|"
                         r"hosts$|resolv\.conf|passwd$|group$)")
        crow = []
        pkg = None
        in_conf = False
        for line in (self.read("/var/lib/dpkg/status", 256 << 20) or "").splitlines():
            if line.startswith("Package: "):
                pkg, in_conf = line[9:], False
            elif line.startswith("Conffiles:"):
                in_conf = True
            elif in_conf and line.startswith(" /"):
                f = line.split()
                if len(f) < 2 or "obsolete" in f[2:] or f[1] == "newconffile":
                    continue
                if not self.deep and not rel.search(f[0]):
                    continue
                try:
                    got = _md5(self.p(f[0]))
                except OSError:
                    continue
                if got != f[1]:
                    st = self.lstat(f[0])
                    crow.append([f[0], pkg, iso(st.st_mtime) if st else ""])
                    if f[0].startswith(("/etc/pam.d/", "/etc/ld.so", "/etc/nsswitch.conf",
                                        "/etc/update-motd.d/", "/etc/sudoers")):
                        self.add("medium" if not f[0].startswith("/etc/sudoers") else "low",
                                 "integrity", "conffile-modified",
                                 f"{f[0]} was modified after installation ({pkg})",
                                 ["T1556.003"] if "pam.d" in f[0] else ["T1546"],
                                 "Security-relevant config differs from the package default. "
                                 "Often a legitimate admin change - diff it against the package.",
                                 "", {"file": f[0], "package": pkg,
                                      "modified": iso(st.st_mtime) if st else "?"}, f[0])
            elif not line.startswith(" "):
                in_conf = False
        self.table("conffiles", "Modified package config files", "integrity",
                   ["file", "package", "modified"], crow, key=[0])

        # unpackaged files dropped into system binary directories
        brow = []
        for d in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"):
            if os.path.islink(self.p(d)):
                continue
            try:
                ents = list(os.scandir(self.p(d)))
            except OSError:
                continue
            for e in ents:
                path = f"{d}/{e.name}"
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    tgt = readlink(e.path) or ""
                    if tgt.startswith(WW_DIRS + ("/home/",)):
                        self.add("high", "integrity", "bin-symlink-ww",
                                 f"{path} points into a user-writable location: {tgt}",
                                 ["T1036.005"], "", "", {"file": path, "target": tgt}, path)
                    continue
                if self.hostinfo.get("container") and e.name == "policy-rc.d":
                    continue                # Docker base images ship this
                if any(v in self._diverted for v in self._variants(path)):
                    continue                # dpkg-divert'ed: a package put it there
                if stat.S_ISREG(st.st_mode) and not self.owner(path):
                    brow.append([path, st.st_size, iso(st.st_mtime), iso(st.st_ctime)])
                    sev = "high" if self.is_recent(st) else "medium"
                    sha = self.grab(path, None, "unpackaged file in system bin dir") \
                        if sev == "high" else None
                    self.add(sev, "integrity", "bin-unpackaged",
                             f"Unpackaged file in {d}: {e.name}", ["T1036.005"],
                             "Attackers drop tools next to real system binaries so they blend "
                             "in. Vendor installers sometimes do the same - verify the source.",
                             "", {"file": path, "size": st.st_size, "modified": iso(st.st_mtime),
                                  "changed": iso(st.st_ctime), "sha256": sha}, path)
        self.table("bin_unpackaged", "Unpackaged files in system bin directories", "integrity",
                   ["file", "size", "modified", "changed"], brow, key=[0])

    # ------------------------------------------------------ filesystem walk
    def c_filesystem(self):
        roots = ["/"] if self.deep else [
            "/tmp", "/var/tmp", "/dev/shm", "/run/shm", "/etc", "/root", "/home", "/usr",
            "/opt", "/srv", "/var/www", "/var/spool", "/var/lib", "/boot", "/bin", "/sbin",
            "/lib", "/lib64", "/usr/local"]
        skip = {"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/containerd",
                "/var/lib/lxcfs", "/var/lib/snapd", "/var/lib/flatpak", "/var/lib/lxd",
                "/var/lib/mysql", "/var/lib/postgresql", "/var/cache"}
        keep_dev = ("/dev/shm", "/run/shm")
        tmp_ok = {".X11-unix", ".ICE-unix", ".font-unix", ".XIM-unix", ".Test-unix",
                  ".X0-lock", ".X1-lock", ".snapshot"}
        web = ("/var/www/", "/srv/", "/usr/share/nginx/")
        watch = ("/etc/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/systemd/",
                 "/lib/systemd/", "/root/", "/var/spool/cron/", "/boot/", "/usr/local/bin/",
                 "/usr/local/sbin/", "/usr/lib/x86_64-linux-gnu/security/",
                 "/lib/x86_64-linux-gnu/security/")
        out_real = os.path.realpath(self.out) if self.out else None
        suid, caps, dropped, recent, shells = [], [], [], [], []
        tmp_groups = {}
        seen_roots = set()
        t0 = time.time()
        n = 0
        cut = False
        for r in roots:
            real = os.path.realpath(self.p(r))
            if real in seen_roots or not os.path.isdir(real):
                continue
            seen_roots.add(real)
            for dp, dns, fns in os.walk(real):
                hp = self.hostpath(dp)
                dns[:] = [d for d in dns
                          if (hp.rstrip("/") + "/" + d) not in skip or
                          (hp.rstrip("/") + "/" + d) in keep_dev]
                if out_real and (dp == out_real or dp.startswith(out_real + "/")):
                    dns[:] = []
                    continue
                in_ww = (hp + "/").startswith(WW_DIRS)
                if in_ww:
                    dns[:] = [d for d in dns if d != ".git"]
                if in_ww:
                    for d in dns:
                        if d not in tmp_ok and (re.fullmatch(r"[.\s]+", d) or
                                                d.startswith(" ") or d.endswith(" ")):
                            path = f"{hp.rstrip('/')}/{d}"
                            dropped.append([path, "hidden dir", "", ""])
                            self.add("medium", "filesystem", "hidden-dir-tmp",
                                     f"Oddly named hidden directory {path!r}", ["T1564.001"],
                                     "Names like '...', '. ' or ' ' in temp dirs are used to "
                                     "hide toolkits from casual ls.", "", {"dir": path}, path)
                for fn in fns:
                    n += 1
                    if n % 2000 == 0 and time.time() - t0 > self.budget:
                        cut = True
                        break
                    fp = os.path.join(dp, fn)
                    try:
                        st = os.lstat(fp)
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    path = self.hostpath(fp)
                    mode = st.st_mode
                    if mode & (stat.S_ISUID | stat.S_ISGID):
                        pk = self.owner(path)
                        kind = ("suid" if mode & stat.S_ISUID else "") + \
                               ("sgid" if mode & stat.S_ISGID else "")
                        suid.append([path, kind, st.st_uid, oct(mode & 0o7777), pk or "",
                                     iso(st.st_mtime)])
                        if not pk and self.owned():
                            bad = path.startswith(WW_DIRS + ("/home/",))
                            sha = self.grab(path, None, f"unpackaged {kind}")
                            self.add("critical" if bad else "high", "filesystem", "suid-unpackaged",
                                     f"Unpackaged {kind.upper()} file {path} (owner uid {st.st_uid})",
                                     ["T1548.001"], "A set-uid root copy of a shell or helper is a "
                                     "one-command way back to root.", "",
                                     {"file": path, "mode": oct(mode & 0o7777), "uid": st.st_uid,
                                      "modified": iso(st.st_mtime), "sha256": sha}, path)
                    if mode & 0o111 and not in_ww:
                        try:
                            raw = os.getxattr(fp, "security.capability", follow_symlinks=False)
                        except OSError:
                            raw = None
                        if raw:
                            cl = decode_caps(raw)
                            pk = self.owner(path)
                            caps.append([path, " ".join(cl), pk or ""])
                            danger = {c[4:] for c in cl} & DANGER_CAPS
                            if not pk and self.owned():
                                self.grab(path, None, "unpackaged file with capabilities")
                                self.add("high" if danger else "medium", "filesystem",
                                         "caps-unpackaged",
                                         f"{path} has file capabilities {' '.join(cl)}",
                                         ["T1548.001"], "cap_setuid / cap_dac_override on an "
                                         "interpreter or copied binary is a quiet root backdoor.",
                                         "", {"file": path, "caps": cl}, path)
                    if in_ww:
                        try:
                            with open(fp, "rb") as fh:
                                head = fh.read(4)
                        except OSError:
                            head = b""
                        kind = "ELF" if head == b"\x7fELF" else (
                            "script" if head[:2] == b"#!" and mode & 0o111 else None)
                        if kind:
                            dropped.append([path, kind, st.st_size, iso(st.st_mtime)])
                            # strong: a real executable (not a .so), anything in /dev/shm,
                            # or a file sitting directly in the temp root. The rest is
                            # usually a checked-out project / venv: grouped per folder.
                            ww_root = next(w for w in WW_DIRS if (path).startswith(w))
                            rel = path[len(ww_root):]
                            lib = re.search(r"\.so(\.[\d.]+)?$", fn) is not None
                            strong = (kind == "ELF" and mode & 0o111 and not lib) or \
                                ww_root in ("/dev/shm/", "/run/shm/") or "/" not in rel
                            if strong:
                                sev = "high" if kind == "ELF" and mode & 0o111 else "medium"
                                sha = self.grab(path, None, f"{kind} in temp dir")
                                self.add(sev, "filesystem", "dropped-file",
                                         f"{'Executable ' if mode & 0o111 else ''}{kind} in "
                                         f"{os.path.dirname(path)}: {os.path.basename(path)}",
                                         ["T1105"], "Downloaded payloads are staged in temp "
                                         "directories because every user can write there.", "",
                                         {"file": path, "size": st.st_size,
                                          "mode": oct(mode & 0o7777), "uid": st.st_uid,
                                          "modified": iso(st.st_mtime), "sha256": sha}, path)
                            else:
                                grp = ww_root + rel.split("/")[0]
                                tmp_groups.setdefault(grp, []).append(f"{kind}: {path}")
                    if path.startswith(web) or re.match(r"^/home/[^/]+/(public_html|www|htdocs)/", path):
                        if fn.lower().endswith(WEB_EXT) and st.st_size < 2 << 20:
                            try:
                                with open(fp, "rb") as fh:
                                    m = WEBSHELL_RE.search(fh.read())
                            except OSError:
                                m = None
                            if m:
                                sha = self.grab(path, None, "web shell signature")
                                shells.append([path, m.group(0)[:80].decode("utf-8", "replace"),
                                               iso(st.st_mtime)])
                                self.add("high", "filesystem", "webshell",
                                         f"Web-shell signature in {path}", ["T1505.003"],
                                         "The file executes request parameters or decodes and "
                                         "evals hidden code - the core of a web shell.", "",
                                         {"file": path, "match": m.group(0)[:120].decode(
                                             "utf-8", "replace"), "sha256": sha,
                                          "modified": iso(st.st_mtime)}, path)
                    if path.startswith(watch) and st.st_ctime >= self.recent:
                        recent.append([path, iso(st.st_ctime), iso(st.st_mtime), st.st_size,
                                       self.owner(path) or "",
                                       ["mtime<ctime"] if st.st_ctime - st.st_mtime > 86400
                                       and not self.owner(path) else []])
                if cut:
                    break
            if cut:
                break
        for grp, items in sorted(tmp_groups.items()):
            self.add("low", "filesystem", "temp-tree",
                     f"{len(items)} script(s)/librar(ies) inside {grp}/", ["T1105"],
                     "Nested inside a folder in a temp dir - typically an unpacked project, "
                     "virtualenv or build tree. Low on its own; review if the folder is "
                     "unexpected.", "", {"folder": grp, "files": items[:30],
                                         "total": len(items)}, grp)
        if cut:
            self.errors.append({"check": "filesystem sweep", "error":
                                f"stopped after --walk-budget {self.budget}s ({n} files); "
                                "raise it for full coverage"})
        self.hostinfo["files_swept"] = n
        recent.sort(key=lambda r: r[1], reverse=True)
        self.table("suid", "SUID / SGID files", "filesystem",
                   ["file", "kind", "uid", "mode", "package", "modified"], suid, key=[0, 1, 4])
        self.table("caps", "Files with capabilities", "filesystem", ["file", "caps", "package"],
                   caps, key=[0, 1])
        self.table("dropped", "Executables and hidden dirs in temp locations", "filesystem",
                   ["path", "kind", "size", "modified"], dropped, key=[0, 1])
        self.table("webshells", "Web-shell signature hits", "filesystem",
                   ["file", "match", "modified"], shells, key=[0])
        self.table("recent_changes", f"System files changed in the last {self.days} days",
                   "filesystem", ["file", "changed", "modified", "size", "package", "flags"],
                   recent[:1500], key=[0],
                   note="ctime is set by the kernel and survives 'touch' timestomping; "
                        "'mtime<ctime' on an unpackaged file hints at a faked timestamp.")

    # =============================================================== output
    def verdict(self):
        c = Counter(f["sev"] for f in self.findings)
        if c["critical"]:
            return "compromised", "Indicators of compromise found"
        if c["high"]:
            return "suspicious", "Suspicious activity - investigate"
        if c["medium"]:
            return "review", "Nothing conclusive - review the medium findings"
        return "clean", "No indicators found (within this tool's limits)"

    def result(self):
        v = self.verdict()
        try:
            me = _sha256(os.path.abspath(__file__))
        except OSError:
            me = None
        used = sorted({t for f in self.findings for t in f["mitre"]})
        return {
            "tool": "procsnap", "kind": "triage", "version": VERSION,
            "started": round(self.now, 3), "duration_s": self.duration,
            "host": self.hostinfo,
            "verdict": {"level": v[0], "text": v[1]},
            "counts": {s: sum(1 for f in self.findings if f["sev"] == s) for s in SEVERITIES},
            "options": {"root": self.root, "days": self.days, "deep": self.deep,
                        "collect": self.collect, "walk_budget": self.budget},
            "findings": self.findings,
            "inventory": self.inv,
            "evidence": self.evidence,
            "errors": self.errors,
            "timings": self.timings,
            "mitre": {t: {"name": MITRE[t][0], "tactic": MITRE[t][1]} for t in used if t in MITRE},
            "tactics": list(TACTICS),
            "self": {"sha256": me, "pid": self.selfpid, "argv": sys.argv},
        }


# ==========================================================================
# baseline DB: what a known-good host of this role runs
# ==========================================================================
def recount(res):
    """Re-sort findings and recompute counts, verdict and ATT&CK after adding findings."""
    res["findings"].sort(key=lambda f: (SEV_RANK[f["sev"]], f["cat"], f["title"]))
    c = Counter(f["sev"] for f in res["findings"])
    res["counts"] = {s: c.get(s, 0) for s in SEVERITIES}
    lvl = ("compromised" if c["critical"] else "suspicious" if c["high"] else
           "review" if c["medium"] else "clean")
    res["verdict"] = {"level": lvl, "text": {
        "compromised": "Indicators of compromise found",
        "suspicious": "Suspicious activity - investigate",
        "review": "Nothing conclusive - review the medium findings",
        "clean": "No indicators found (within this tool's limits)"}[lvl]}
    used = sorted({t for f in res["findings"] for t in f["mitre"]})
    res["mitre"] = {t: {"name": MITRE[t][0], "tactic": MITRE[t][1]} for t in used if t in MITRE}


def _rows(res, name):
    t = (res.get("inventory") or {}).get(name)
    if not t:
        return []
    return [dict(zip(t["cols"], r)) for r in t["rows"]]


def _cron_key(r):
    src = r["source"]
    if src.startswith("/var/spool/cron/"):                 # user crontabs: per user, not path
        src = "crontab:" + r["user"]
    cmd = re.sub(r"\s+", " ", r["command"]).strip()
    return f"{src}|{cmd}"


def mkbaseline(files):
    db = {"kind": "procsnap-baseline", "version": 1, "created": round(time.time()),
          "hosts": [], "services": {}, "cron": {}}
    for fp in files:
        with open(fp) as fh:
            res = json.load(fh)
        if res.get("kind") != "triage":
            raise SystemExit(f"{fp}: not a triage.json")
        h = res["host"]
        db["hosts"].append({"hostname": h.get("hostname"), "os": h.get("os"),
                            "triaged": res.get("started"), "verdict": res["verdict"]["level"]})
        if res["verdict"]["level"] == "compromised":
            print(f"[!] {fp}: this triage has critical findings - a baseline should come from a "
                  "known-clean host", file=sys.stderr)
        for r in _rows(res, "services"):
            e = db["services"].setdefault(f"{r['scope']}:{r['unit']}",
                                          {"exec_paths": [], "exec_sha256": [], "default": []})
            for k, v in (("exec_paths", r["exec path"]), ("exec_sha256", r["exec sha256"]),
                         ("default", r["default"])):
                if v and v not in e[k]:
                    e[k].append(v)
        for r in _rows(res, "cron"):
            e = db["cron"].setdefault(_cron_key(r), {"exec_paths": [], "exec_sha256": []})
            for k, v in (("exec_paths", r["exec path"]), ("exec_sha256", r["exec sha256"])):
                if v and v not in e[k]:
                    e[k].append(v)
    return db


def apply_baseline(res, db):
    """Add findings for services/cron jobs that differ from the baseline DB. -> count"""
    if db.get("kind") != "procsnap-baseline":
        raise SystemExit("not a procsnap baseline DB (build one with: procsnap.py mkbaseline)")
    added = 0

    def add(sev, check, title, why, ev, key):
        nonlocal added
        fid = hashlib.sha1(f"{check}|{key}".encode()).hexdigest()[:12]
        if any(f["id"] == fid for f in res["findings"]):
            return
        res["findings"].append({"id": fid, "sev": sev, "cat": "persistence", "check": check,
                                "title": title, "mitre": ["T1543.002"] if "service" in check
                                else ["T1053.003"], "why": why, "fix": "", "evidence": ev})
        added += 1

    hosts = ", ".join(sorted({h["hostname"] or "?" for h in db["hosts"]}))[:80]
    for r in _rows(res, "services"):
        k = f"{r['scope']}:{r['unit']}"
        b = db["services"].get(k)
        ev = {"unit": r["unit"], "exec_path": r["exec path"], "exec_sha256": r["exec sha256"],
              "exec_package": r["exec package"], "baseline_hosts": hosts}
        if b is None:
            sev = "high" if (r["exec path"] and not r["exec package"]) else "medium"
            add(sev, "baseline-new-service", f"Service {r['unit']} is not in the baseline",
                "No known-good host of this role has this unit.", ev, k)
        elif r["exec path"] and b["exec_paths"] and r["exec path"] not in b["exec_paths"]:
            add("high", "baseline-service-exec-path",
                f"Service {r['unit']} runs {r['exec path']} - baseline: "
                f"{', '.join(b['exec_paths'][:2])}",
                "Same service name, different program: the classic way to hijack a trusted "
                "service.", dict(ev, baseline_paths=b["exec_paths"]), k)
        elif r["exec sha256"] and b["exec_sha256"] and r["exec sha256"] not in b["exec_sha256"] \
                and not r["exec package"]:
            add("high", "baseline-service-exec-hash",
                f"Service {r['unit']}: {r['exec path']} differs from the baseline binary",
                "Same path, different content. (Package-owned binaries are skipped: version "
                "upgrades change them and dpkg verifies them.)",
                dict(ev, baseline_sha256=b["exec_sha256"]), k)
    for r in _rows(res, "cron"):
        k = _cron_key(r)
        b = db["cron"].get(k)
        ev = {"source": r["source"], "user": r["user"], "schedule": r["schedule"],
              "command": r["command"], "exec_path": r["exec path"],
              "exec_sha256": r["exec sha256"], "baseline_hosts": hosts}
        if b is None:
            add("high" if (r["exec path"] and not r["exec package"]) else "medium",
                "baseline-new-cron", f"Cron job not in the baseline: {r['source']} "
                f"({r['user']}) {r['command'][:70]}", "No known-good host of this role runs "
                "this job.", ev, k)
        elif r["exec sha256"] and b["exec_sha256"] and r["exec sha256"] not in b["exec_sha256"] \
                and not r["exec package"]:
            add("high", "baseline-cron-exec-hash",
                f"Cron job {r['source']}: {r['exec path']} differs from the baseline",
                "", dict(ev, baseline_sha256=b["exec_sha256"]), k)
    res.setdefault("baseline", {})["db"] = {"hosts": db["hosts"], "created": db["created"],
                                            "services": len(db["services"]),
                                            "cron": len(db["cron"]), "findings": added}
    recount(res)
    return added


def cmd_mkbaseline(a):
    db = mkbaseline(a.triage)
    with open(a.out, "w") as fh:
        json.dump(db, fh, indent=1)
    print(f"[+] {a.out}: {len(db['services'])} services, {len(db['cron'])} cron jobs from "
          f"{len(db['hosts'])} host(s)")


def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text


SEV_TTY = {"critical": "1;97;41", "high": "1;31", "medium": "1;33", "low": "36", "info": "2"}


def print_triage(res, limit=60, out=None):
    out = out or sys.stdout

    def say(*a):
        print(*a, file=out)
    h = res["host"]
    say(_c("1", f"\nprocsnap triage · {h.get('hostname')}") +
          f"   {h.get('os')}  {h.get('kernel', '')}   [{h.get('mode')}]")
    v = res["verdict"]
    vc = {"compromised": "1;97;41", "suspicious": "1;31", "review": "1;33", "clean": "1;32"}[v["level"]]
    say("  verdict : " + _c(vc, f" {v['text'].upper()} "))
    say("  findings: " + "  ".join(_c(SEV_TTY[s], f"{res['counts'][s]} {s}")
                                    for s in SEVERITIES))
    say(f"  took {res['duration_s']}s · {len(res['evidence'])} evidence file(s) hashed")
    sess = res["inventory"].get("sessions")
    if sess and sess["rows"]:
        c = sess["cols"]
        say("  logged in now: " + "; ".join(
            f"{r[c.index('user')]}@{r[c.index('tty')]} from {r[c.index('from')]} "
            f"for {r[c.index('session length')]}" for r in sess["rows"][:6]))
    shown = 0
    for sev in SEVERITIES[:-1]:
        fs = [f for f in res["findings"] if f["sev"] == sev]
        if not fs:
            continue
        say("\n" + _c(SEV_TTY[sev], f" {sev.upper()} ") + f"  ({len(fs)})")
        for f in fs:
            if shown >= limit:
                break
            mt = (" " + _c("2", ",".join(f["mitre"]))) if f["mitre"] else ""
            say(f"  • {f['title'][:150]}{mt}")
            shown += 1
    if shown >= limit:
        say(_c("2", f"\n  ... {len(res['findings']) - shown} more in the JSON / HTML report"))
    if res["errors"]:
        say("\n" + _c("2", "notes:"))
        for e in res["errors"]:
            say(_c("2", f"  - [{e['check']}] {e['error']}"))
    say()


def cmd_triage(a):
    host = socket.gethostname() if (a.root or "/") == "/" else os.path.basename(
        os.path.abspath(a.root).rstrip("/")) or "image"
    if a.out is None:
        a.out = f"triage-{host}-{time.strftime('%Y%m%d-%H%M%S')}"
    if a.out:
        os.makedirs(a.out, mode=0o700, exist_ok=True)
    t = Triage(a)
    t.run()
    res = t.result()
    if a.baseline:
        with open(a.baseline) as fh:
            n = apply_baseline(res, json.load(fh))
        print(f"[*] baseline: {n} difference(s) from {a.baseline}", file=sys.stderr)
    # with -o '' stdout carries the JSON, so the human summary goes to stderr
    print_triage(res, a.limit, sys.stdout if a.out else sys.stderr)
    if not a.out:
        json.dump(res, sys.stdout, default=str)
        return
    jpath = os.path.join(a.out, "triage.json")
    with open(jpath, "w") as fh:
        json.dump(res, fh, indent=1, default=str)
    print(f"[+] {jpath}")
    if not a.no_html:
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import procsnap_viz                                   # noqa: E402
            base = None
            if a.compare:
                with open(a.compare) as fh:
                    base = json.load(fh)
            hpath = os.path.join(a.out, "triage.html")
            with open(hpath, "w") as fh:
                fh.write(procsnap_viz.render_triage(res, base))
            print(f"[+] {hpath}")
        except ImportError:
            print("[i] procsnap_viz.py not next to procsnap.py - render later with:\n"
                  f"    procsnap_viz.py {jpath}", file=sys.stderr)
    with open(os.path.join(a.out, "HASHES.txt"), "w") as fh:
        for fn in sorted(os.listdir(a.out)):
            fp = os.path.join(a.out, fn)
            if os.path.isfile(fp) and fn != "HASHES.txt":
                fh.write(f"{_sha256(fp)}  {fn}\n")
        for e in res["evidence"]:
            if e.get("saved"):
                fh.write(f"{e['sha256']}  {e['saved']}\n")


def triage_diff(old, new):
    """-> {'findings': {'new': [...], 'gone': [...]}, 'inventory': {name: {'added','removed'}}}"""
    oi = {f["id"]: f for f in old["findings"]}
    ni = {f["id"]: f for f in new["findings"]}
    out = {"findings": {"new": [ni[k] for k in ni if k not in oi],
                        "gone": [oi[k] for k in oi if k not in ni]},
           "inventory": {}}
    for name, nt in new["inventory"].items():
        ot = old["inventory"].get(name)
        if not ot:
            continue
        key = nt.get("key") or list(range(len(nt["cols"])))

        def k(row):
            return json.dumps([row[i] for i in key if i < len(row)], default=str)
        ok = {k(r): r for r in ot["rows"]}
        nk = {k(r): r for r in nt["rows"]}
        add = [nk[x] for x in nk if x not in ok]
        rem = [ok[x] for x in ok if x not in nk]
        if add or rem:
            out["inventory"][name] = {"title": nt["title"], "cols": nt["cols"],
                                      "added": add[:500], "removed": rem[:500]}
    return out


def cmd_triage_diff(a):
    with open(a.old) as fh:
        old = json.load(fh)
    with open(a.new) as fh:
        new = json.load(fh)
    d = triage_diff(old, new)
    print(_c("1", f"triage diff  {old['host'].get('hostname')} {iso(old['started'])}  ->  "
                  f"{new['host'].get('hostname')} {iso(new['started'])}"))
    for label, fs, col in (("NEW findings", d["findings"]["new"], "1;31"),
                           ("RESOLVED findings", d["findings"]["gone"], "1;32")):
        print("\n" + _c(col, f"{label} ({len(fs)})"))
        for f in sorted(fs, key=lambda f: SEV_RANK[f["sev"]]):
            print(f"  {_c(SEV_TTY[f['sev']], f['sev'][:4].upper())}  {f['title'][:140]}")
    for name, x in d["inventory"].items():
        print("\n" + _c("1", f"{x['title']}") + f"  +{len(x['added'])} / -{len(x['removed'])}")
        for r in x["added"][:a.limit]:
            print(_c("32", "  + " + " | ".join(str(c) for c in r if not isinstance(c, list))[:170]))
        for r in x["removed"][:a.limit]:
            print(_c("31", "  - " + " | ".join(str(c) for c in r if not isinstance(c, list))[:170]))
    print()


# --------------------------------------------------------------------------
# Host data (command lines, file names, hostnames) is attacker-controlled. Printed
# raw it could retitle or clear the analyst's terminal, or fake output, with escape
# sequences. Everything written to the console passes through this filter: our own
# colour codes (ESC [ digits m) survive, every other control character is replaced.
_CTRL = re.compile(r"\x1b(?!\[[0-9;]*m)|[\x00-\x08\x0b-\x1a\x1c-\x1f\x7f-\x9f]")


class SafeConsole:
    def __init__(self, stream):
        self._s = stream

    def write(self, text):
        return self._s.write(_CTRL.sub("\ufffd", text))

    def __getattr__(self, name):
        return getattr(self._s, name)


def protect_console():
    if not isinstance(sys.stdout, SafeConsole):
        sys.stdout = SafeConsole(sys.stdout)
        sys.stderr = SafeConsole(sys.stderr)


# --------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(
        description="procsnap - periodic process + network snapshotter",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="run the collector")
    c.add_argument("-i", "--interval", type=duration, default=10.0, metavar="DUR",
                   help="gap between snapshots: 10, 30s, 5m, 1h (default 10s)")
    c.add_argument("-o", "--out", default="/var/log/procsnap", help="output directory")
    c.add_argument("--stdout", action="store_true", help="also stream JSONL to stdout")
    c.add_argument("--gzip", action="store_true", help="gzip the daily log")
    c.add_argument("--count", type=int, default=0, help="stop after N snapshots")
    c.add_argument("--retain-days", type=int, default=14, help="prune older logs (0=keep)")
    c.add_argument("--full-every", type=int, default=360,
                   help="write a full inventory every N snapshots (0=never)")
    c.add_argument("--no-net", action="store_true", help="processes only, skip sockets")
    c.add_argument("--no-kthreads", action="store_true", help="skip kernel threads")
    c.add_argument("--no-loopback", action="store_true", help="skip loopback connections")
    c.add_argument("--include-timewait", action="store_true")
    c.add_argument("--no-hash", action="store_true",
                   help="do not SHA-256 each new process's executable")
    c.set_defaults(func=cmd_collect)

    r = sub.add_parser("report", help="summary of a log directory")
    r.add_argument("path")
    r.add_argument("--since")
    r.add_argument("--top", type=int, default=20)
    r.set_defaults(func=cmd_report)

    t = sub.add_parser("timeline", help="chronological event list")
    t.add_argument("path")
    t.add_argument("--since")
    t.add_argument("--grep")
    t.add_argument("--ev", help="comma list, e.g. proc_start,conn_open")
    t.add_argument("--baseline", action="store_true", help="include first-snapshot baseline")
    t.add_argument("--limit", type=int, default=0)
    t.set_defaults(func=cmd_timeline)

    pr = sub.add_parser("procs", help="aggregate process executions")
    pr.add_argument("path")
    pr.add_argument("--since")
    pr.add_argument("--grep")
    pr.add_argument("--top", type=int, default=40)
    pr.set_defaults(func=cmd_procs)

    cn = sub.add_parser("conns", help="aggregate network connections")
    cn.add_argument("path")
    cn.add_argument("--since")
    cn.add_argument("--remote", help="substring match on remote IP")
    cn.add_argument("--port", type=int)
    cn.add_argument("--external-only", action="store_true")
    cn.add_argument("--top", type=int, default=40)
    cn.add_argument("-v", "--verbose", action="store_true")
    cn.set_defaults(func=cmd_conns)

    sn = sub.add_parser("snapshots", help="list the snapshot points in a log")
    sn.add_argument("path")
    sn.add_argument("--since")
    sn.add_argument("--limit", type=int, default=40, help="max rows (0=all)")
    sn.set_defaults(func=cmd_snapshots)

    sh = sub.add_parser("show", help="print full host state at one snapshot")
    sh.add_argument("path")
    sh.add_argument("--at", default="last",
                    help="#N | first | last | HH:MM:SS | epoch (default: last)")
    sh.add_argument("--pid", action="store_true", help="include PIDs in the lines")
    sh.add_argument("--no-kthreads", action="store_true")
    sh.set_defaults(func=cmd_show)

    df = sub.add_parser("diff", help="compare two or more snapshots line by line")
    df.add_argument("path")
    df.add_argument("--at", action="append", required=True,
                    help="repeat 2+ times: --at '#1' --at '#20' --at 03:14:00")
    df.add_argument("--pid", action="store_true",
                    help="treat different PIDs as different lines")
    df.add_argument("--no-kthreads", action="store_true")
    df.add_argument("-v", "--verbose", action="store_true", help="show exe paths")
    df.set_defaults(func=cmd_diff)

    sq = sub.add_parser("sqlite", help="export to a SQLite db for ad-hoc SQL")
    sq.add_argument("path")
    sq.add_argument("-o", "--out", default="procsnap.db")
    sq.add_argument("--force", action="store_true")
    sq.set_defaults(func=cmd_sqlite)

    on = sub.add_parser("once", help="take a single snapshot and exit")
    on.add_argument("-o", "--out", default=".",
                    help="output directory (default: cwd; use '' for stdout only)")
    on.add_argument("--stdout", action="store_true", help="stream JSONL to stdout")
    on.add_argument("--no-net", action="store_true", help="processes only, skip sockets")
    on.add_argument("--no-kthreads", action="store_true", help="skip kernel threads")
    on.add_argument("--no-loopback", action="store_true", help="skip loopback connections")
    on.add_argument("--include-timewait", action="store_true")
    on.add_argument("--no-hash", action="store_true", help="do not hash executables")
    on.set_defaults(func=cmd_once, interval=0.0)

    tr = sub.add_parser("triage", help="one-shot compromise assessment (live host or image)",
                        description="Live triage: processes, network, kernel, persistence, "
                                    "accounts, logins, package integrity and a filesystem sweep. "
                                    "Writes triage.json, triage.html, evidence/ and HASHES.txt.")
    tr.add_argument("-o", "--out", default=None,
                    help="case directory (default ./triage-<host>-<time>; '' = JSON to stdout)")
    tr.add_argument("--root", default="/",
                    help="mounted image to triage offline (default / = this live host)")
    tr.add_argument("--days", type=int, default=7, help="'recent' window in days (default 7)")
    tr.add_argument("--deep", action="store_true",
                    help="verify every packaged file, scan all PIDs, sweep the whole filesystem")
    tr.add_argument("--no-collect", action="store_true",
                    help="hash suspicious files but do not copy them into evidence/")
    tr.add_argument("--evidence-mb", type=int, default=50, help="max size of a copied sample")
    tr.add_argument("--walk-budget", type=int, default=240,
                    help="seconds allowed for the filesystem sweep (default 240)")
    tr.add_argument("--compare", metavar="OLD.json",
                    help="earlier triage.json of this (or a golden) host: adds a Changes view")
    tr.add_argument("--baseline", metavar="DB.json",
                    help="baseline DB (procsnap.py mkbaseline): flag services/cron jobs that "
                         "are new or whose executable path/hash differs")
    tr.add_argument("--no-html", action="store_true")
    tr.add_argument("--limit", type=int, default=60, help="findings printed to the terminal")
    tr.add_argument("-q", "--quiet", action="store_true", help="no progress lines")
    tr.set_defaults(func=cmd_triage)

    mb = sub.add_parser("mkbaseline", help="build a baseline DB from known-good triage.json files",
                        description="Merge one or more triage.json files from known-good hosts "
                                    "of the same role into a DB of expected services and cron "
                                    "jobs with their executable paths and SHA-256s.")
    mb.add_argument("triage", nargs="+", help="triage.json files from clean hosts")
    mb.add_argument("-o", "--out", default="baseline.json")
    mb.set_defaults(func=cmd_mkbaseline)

    td = sub.add_parser("triage-diff", help="compare two triage.json files")
    td.add_argument("old")
    td.add_argument("new")
    td.add_argument("--limit", type=int, default=40, help="rows per changed table")
    td.set_defaults(func=cmd_triage_diff)

    it = sub.add_parser("install-service", help="emit/install a systemd unit")
    it.add_argument("-i", "--interval", type=duration, default=10.0, metavar="DUR")
    it.add_argument("-o", "--out", default="/var/log/procsnap")
    it.add_argument("--retain-days", type=int, default=14)
    it.add_argument("--print-only", action="store_true")
    it.set_defaults(func=cmd_install_service)

    a = p.parse_args()
    protect_console()
    try:
        a.func(a)
    except BrokenPipeError:
        os._exit(0)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
