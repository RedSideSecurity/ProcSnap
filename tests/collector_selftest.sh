#!/bin/bash
# procsnap collector self-test
#
# Runs the continuous collector at a 1s interval for ~22s while six harmless
# "suspicious" processes run, then checks the log really contains each of them
# (flags, beacon detection, lifetimes) and renders the timeline HTML report.
#
#   sudo tests/collector_selftest.sh [case-dir]
#
# Everything is local (127.0.0.1) and removed on exit.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CASE="${1:-/tmp/procsnap-collector-test}"
WORK=$(mktemp -d /tmp/procsnap-ct.XXXXXX)
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill -- -"$p" 2>/dev/null; kill "$p" 2>/dev/null; done
  [ -n "${COL:-}" ] && kill "$COL" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT
spawn() { setsid "$@" </dev/null >/dev/null 2>&1 & PIDS+=($!); }

rm -rf "$CASE"; mkdir -p "$CASE"
echo "[*] collector: 1s interval -> $CASE"
python3 "$HERE/procsnap.py" collect -i 1s -o "$CASE" --retain-days 0 >/dev/null 2>&1 &
COL=$!
sleep 2.5

echo "[*] plant 1: exe in /tmp named like a miner";   cp /bin/sleep "$WORK/xmrig"; spawn "$WORK/xmrig" 18
echo "[*] plant 2: binary deleted after start";                  cp /bin/sleep "$WORK/gone"; spawn "$WORK/gone" 18
sleep 1.6; rm -f "$WORK/gone"     # seen first, deleted later -> exe_deleted event
echo "[*] plant 3: decode-and-run command line";       spawn bash -c 'echo aGVsbG8K | base64 -d >/dev/null; sleep 18; :'
echo "[*] plant 4: listener on 0.0.0.0 high port";     spawn python3 -m http.server 44444 --bind 0.0.0.0
echo "[*] plant 5: beacon - same peer every ~3s";      spawn python3 -c '
import socket, time
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 44445)); srv.listen(8); srv.setblocking(False)
held = []
for i in range(6):
    c = socket.create_connection(("127.0.0.1", 44445))
    try: held.append(srv.accept()[0])
    except BlockingIOError: pass
    time.sleep(2.2); c.close(); time.sleep(0.8)'
echo "[*] plant 6: short-lived burst";                 for i in 1 2 3; do spawn sleep 3; done

echo "[*] collecting 20s..."
sleep 20
kill "$COL"; wait "$COL" 2>/dev/null; COL=""

echo "[*] verifying"
python3 - "$HERE" "$CASE" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
import procsnap as ps, procsnap_viz as viz
d = viz.build(sys.argv[2])
flags = {t for lvl in d["findings"].values() for t in lvl}
exits = d["meta"]["exits"]
beacon = [x for x in d["dests"] if x["port"] == 44445 and x["beacon"]]
checks = [
  ("exe in world-writable dir",  "exe-in-world-writable" in flags),
  ("deleted executable",         "exe-deleted" in flags),
  ("suspicious cmdline",         "suspicious-cmdline" in flags),
  ("0.0.0.0 high-port listener", "listen-all-ifaces-highport" in flags),
  ("beacon detected",            bool(beacon)),
  ("short-lived procs recorded", sum(p["n"] for p in d["procs"] if p["cmd"] == "sleep 3") >= 3
                                 and exits >= 3),
  ("collector_stop written",     any(e.get("ev") == "collector_stop" for e in ps.load(sys.argv[2]))),
]
for label, ok in checks:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
if beacon:
    b = beacon[0]["beacon"]
    print(f"        beacon: every {b['avg']}s, jitter {b['jitter']}s, {b['hits']} hits")
n = sum(ok for _, ok in checks)
print(f"\n  {n}/{len(checks)} collector checks passed")
sys.exit(0 if n == len(checks) else 1)
EOF
rc=$?
python3 "$HERE/procsnap_viz.py" "$CASE" -o "$CASE/report.html" | head -1
exit $rc
