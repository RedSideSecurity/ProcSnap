#!/bin/bash
# procsnap live attack simulation
#
# Starts 13 harmless processes that LOOK like a compromised host (fileless binary,
# fake kernel thread, reverse shell to localhost, miner name, LD_PRELOAD, packet
# socket, bind shell, www-data shell...), runs `procsnap.py triage`, checks that
# every one is detected, then kills and removes everything it created.
#
#   sudo tests/live_attack_sim.sh [case-dir]
#
# Nothing leaves the host: all sockets are on 127.0.0.1, nothing under /etc is
# touched (persistence is covered by the offline fixture in tests/test_triage.py).
set -u
[ "$(id -u)" = 0 ] || { echo "run as root (needs packet sockets, runuser, /proc of other users)"; exit 2; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CASE="${1:-/tmp/psnap-sim-case}"
SIM=/tmp/psnap-sim
PIDS=()

cleanup() {
  # every plant runs in its own session (setsid): kill those sessions only.
  # (never 'pkill -f': it would also match whoever ran this script)
  for p in "${PIDS[@]:-}"; do kill -- -"$p" 2>/dev/null; kill "$p" 2>/dev/null; done
  sleep 0.3
  rm -rf "$SIM" /dev/shm/psnap-sim-x
}
trap cleanup EXIT
rm -rf "$SIM" /dev/shm/psnap-sim-x; mkdir -p "$SIM/..."
spawn() { setsid "$@" </dev/null >/dev/null 2>&1 & PIDS+=($!); }

echo "[*] planting"
# 1 fileless: binary copied into a memfd and exec'd from memory
spawn python3 -c 'import os; fd=os.memfd_create("psnap-sim"); os.write(fd, open("/bin/sleep","rb").read()); os.execv("/proc/self/fd/%d" % fd, ["psnap-sim-memfd","300"])'
# 2 user process posing as a kernel thread, run from /tmp
cp /bin/sleep "$SIM/kw";   spawn bash -c "exec -a '[kworker/1:3-events]' $SIM/kw 300"
# 3 binary deleted after start
cp /bin/sleep "$SIM/gone"; spawn "$SIM/gone" 301; sleep 0.3; rm -f "$SIM/gone"
# 4 miner name
cp /bin/sleep "$SIM/xmrig"; spawn "$SIM/xmrig" 302
# 5 reverse shell: bash whose stdin/stdout is a TCP socket (to a local listener)
spawn python3 -c 'import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",47011)); s.listen(1); c,_=s.accept(); time.sleep(300)  # psnap-sim'
sleep 0.5
spawn bash -c 'exec 0<>/dev/tcp/127.0.0.1/47011 1>&0; sleep 303; : psnap-sim'
# 6 LD_PRELOAD of an unpackaged library
cp "$(ldconfig -p | awk '/libz\.so\.1 /{print $NF; exit}')" "$SIM/libsim.so"
spawn env LD_PRELOAD="$SIM/libsim.so" sleep 304
# 7 shell running as the web server user
spawn runuser -u www-data -- bash -c 'sleep 305; : psnap-sim'
# 8 packet socket held by an unpackaged-looking process (sniffer / BPFDoor shape)
spawn python3 -c 'import socket,time; s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0); time.sleep(300)  # psnap-sim'
# 9 bind shell shape: netcat listening (skipped when nc is not installed)
HAVE_NC=0
command -v nc >/dev/null && { HAVE_NC=1; spawn nc -l 127.0.0.1 47012; }
# 10 ELF dropped in /dev/shm
cp /bin/true /dev/shm/psnap-sim-x
# 11 hidden "..." directory in /tmp  (created above)
# 12 download-and-decode style command line
spawn bash -c 'echo cHNuYXAtc2ltCg== | base64 -d >/dev/null; sleep 306; :'
# 13 process working inside /dev/shm
spawn bash -c 'cd /dev/shm && exec sleep 307'
sleep 1.5

echo "[*] triage"
rm -rf "$CASE"
python3 "$HERE/procsnap.py" triage -o "$CASE" -q --limit 25 --walk-budget 300
echo "[*] verifying"
python3 - "$CASE/triage.json" "$HAVE_NC" <<'EOF'
import json, sys
r = json.load(open(sys.argv[1]))
have_nc = sys.argv[2] == "1"
fs = r["findings"]
want = [
  ("memfd-exe",             "psnap-sim",      "fileless process (memfd)"),
  ("kthread-masquerade",    "kworker/1:3",    "fake kernel thread"),
  ("exe-deleted",           "/tmp/psnap-sim/gone", "deleted executable"),
  ("miner",                 "xmrig",          "miner name"),
  ("reverse-shell",         "bash",           "reverse shell (TCP stdin)"),
  ("ld-preload-env",        "libsim.so",      "LD_PRELOAD injection"),
  ("service-spawned-shell", "www-data",       "shell as www-data"),
  ("raw-socket",            "packet",         "packet socket"),
  ("listener-shell-tool",   "47012",          "netcat bind listener"),
  ("dropped-file",          "psnap-sim-x",    "ELF in /dev/shm"),
  ("hidden-dir-tmp",        "psnap-sim/...",  "hidden '...' dir"),
  ("suspicious-cmdline",    "base64 -d",      "decode-and-run cmdline"),
  ("cwd-world-writable",    "/dev/shm",       "cwd in /dev/shm"),
  ("exe-world-writable",    "/tmp/psnap-sim", "exe in /tmp"),
]
if not have_nc:
    print("  SKIP  netcat bind listener         (nc not installed)")
    want = [w for w in want if w[0] != "listener-shell-tool"]
ok = 0
for check, needle, label in want:
    hit = [f for f in fs if f["check"] == check and needle in json.dumps(f)]
    s = hit[0]["sev"] if hit else "-"
    print(f"  {'PASS' if hit else 'FAIL'}  {label:<28} {check:<22} {s}")
    ok += bool(hit)
print(f"\n  {ok}/{len(want)} simulated techniques detected; verdict: {r['verdict']['text']}")
sys.exit(0 if ok == len(want) else 1)
EOF
rc=$?
echo "[*] report: $CASE/triage.html"
exit $rc
