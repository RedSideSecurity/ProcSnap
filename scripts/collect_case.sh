#!/bin/bash
# ProcSnap target-side case collector
#
# Runs ON THE SUSPECT HOST. Needs only bash, python3, tar and sha256sum, and never
# touches the network. Produces one archive to carry to the analysis machine:
#
#   procsnap-<host>-<UTC time>.tar.gz          the case
#   procsnap-<host>-<UTC time>.tar.gz.sha256   its hash (record it in your case notes)
#
# Inside: triage/ (triage.json, evidence/, HASHES.txt), collector/ (optional watch
# period, JSONL), case.json (who/when/how) and collect.log.
#
#   sudo ./collect_case.sh                      # triage only (~1 min)
#   sudo ./collect_case.sh -w 30m -i 5s         # triage, then watch 30 min at 5 s
#   sudo ./collect_case.sh -o /mnt/usb --deep   # write to removable media, deep triage
#
# Then, on the analysis machine:
#   ./procsnap_analyze.py procsnap-<host>-<time>.tar.gz --vt-key "$VT_API_KEY"
set -u
VERSION=2.0.0
OUT=/var/tmp
WATCH=""
INTERVAL=5s
DEEP=""
DAYS=7
KEEP=""
usage() { sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; echo
  echo "options: -o DIR  -w DURATION (e.g. 30m)  -i INTERVAL (default 5s)  -d DAYS  --deep  --keep-dir"; exit "${1:-0}"; }
need() { [ $# -ge 2 ] && [ -n "$2" ] || { echo "option $1 needs a value"; usage 2; }; }
while [ $# -gt 0 ]; do
  case "$1" in
    -o) need "$@"; OUT="$2"; shift 2;;
    -w) need "$@"; WATCH="$2"; shift 2;;
    -i) need "$@"; INTERVAL="$2"; shift 2;;
    -d) need "$@"; DAYS="$2"; shift 2;;
    --deep) DEEP=--deep; shift;;
    --keep-dir) KEEP=1; shift;;
    -h|--help) usage 0;;
    *) echo "unknown option $1"; usage 2;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
PS=""
# only next to this script (never the current directory of a possibly compromised host)
for c in "$HERE/procsnap.py" "$HERE/../procsnap.py"; do
  [ -n "$c" ] && [ -f "$c" ] && { PS="$c"; break; }
done
[ -n "$PS" ] || { echo "[!] procsnap.py not found next to this script"; exit 2; }
command -v python3 >/dev/null || { echo "[!] python3 is required"; exit 2; }
[ "$(id -u)" = 0 ] || echo "[!] not root - the triage will be partial (other users' processes, /etc/shadow, sockets)"

HOST=$(hostname 2>/dev/null || cat /etc/hostname)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
NAME="procsnap-${HOST}-${STAMP}"
CASE="$OUT/$NAME"
umask 077
mkdir -p "$CASE" || exit 2
LOG="$CASE/collect.log"
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

log "ProcSnap case collector $VERSION on $HOST -> $CASE"
log "tool: $PS  sha256 $(sha256sum "$PS" | cut -d' ' -f1)"
START=$(date -u +%FT%TZ)

log "triage starting"
python3 "$PS" triage -o "$CASE/triage" --no-html -q --days "$DAYS" $DEEP 2>>"$LOG" | tee -a "$LOG"
TRC=${PIPESTATUS[0]}
log "triage finished (rc=$TRC)"

if [ -n "$WATCH" ]; then
  log "watching for $WATCH at $INTERVAL (Ctrl+C stops early and still packages the case)"
  trap 'log "interrupted - packaging what was collected"' INT
  timeout -s TERM "$WATCH" python3 "$PS" collect -i "$INTERVAL" -o "$CASE/collector" \
    --retain-days 0 --gzip 2>>"$LOG"
  trap - INT
  log "watch finished"
fi

# written by python so every value is JSON-escaped (hostname and paths are host data)
python3 - "$CASE/case.json" "$VERSION" "$HOST" "$START" "${WATCH:-none}" "$INTERVAL" \
    "${DEEP:-}" "$(id -u)" "$(uname -r)" "$(sha256sum "$PS" | cut -d' ' -f1)" "$TRC" <<'PYEOF'
import json, sys, time
out, ver, host, start, watch, interval, deep, uid, kernel, sha, trc = sys.argv[1:]
json.dump({"tool": "procsnap", "kind": "case", "collector_version": ver, "host": host,
           "started": start, "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "watch": watch, "interval": interval, "deep": bool(deep), "uid": int(uid),
           "kernel": kernel, "procsnap_sha256": sha, "triage_exit_code": int(trc)},
          open(out, "w"), indent=1)
PYEOF

log "packaging"
if tar -C "$OUT" -czf "$CASE.tar.gz" "$NAME" && sha256sum "$CASE.tar.gz" > "$CASE.tar.gz.sha256"; then
  [ -z "$KEEP" ] && rm -rf "$CASE"
else
  # never delete the evidence when the archive could not be written (disk full...)
  log "PACKAGING FAILED - the case directory is kept: $CASE"
  rm -f "$CASE.tar.gz" "$CASE.tar.gz.sha256"
  exit 3
fi
echo
echo "case archive : $CASE.tar.gz ($(du -h "$CASE.tar.gz" | cut -f1))"
echo "sha256       : $(cut -d' ' -f1 "$CASE.tar.gz.sha256")"
echo "copy it off  : scp root@$HOST:$CASE.tar.gz* ."
echo "analyse      : ./procsnap_analyze.py $NAME.tar.gz [--vt-key KEY]"
if [ "$TRC" != 0 ]; then
  echo "[!] the triage step exited with code $TRC - see collect.log inside the archive"
  exit 4
fi
