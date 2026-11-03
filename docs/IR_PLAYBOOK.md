# ProcSnap — IR Team Playbook

ProcSnap has two engines:

* **`triage`**: a one-shot compromise assessment of a live host (or a mounted disk
  image). It answers *is this box compromised, how did they get in, how are they
  staying?* in about a minute.
* **`collect`**: a continuous process/network recorder. It answers *what happened,
  and when?* over hours or days.

Use triage first on every suspect host; use the collector when you need history or
need to watch something recur. The collector has two deployment modes, and which one
you are in determines everything downstream.

* **Mode A — Continuous (preferred).** Collector already running as a service on the
  fleet. When an alert fires you have *history from before the incident*.
* **Mode B — Live response.** Host is already suspect, collector is not running.
  You only get data from now forward. Weaker, but still valuable for active threats.

---

## TRIAGE — the first ten minutes on a suspect host

Copy two files, run one command, take the case folder away:

    scp procsnap.py procsnap_viz.py root@target:/root/
    ssh root@target 'python3 /root/procsnap.py triage -o /root/case-1234'
    scp -r root@target:/root/case-1234 ./ && sha256sum -c case-1234/HASHES.txt

* **Write the case off the suspect disk** when you can: `-o /mnt/usb/case-1234`, or
  `-o ''` to stream the JSON over ssh (`... triage -o '' > case.json`, then render it
  with `procsnap_viz.py case.json`).
* Read `triage.html` in this order: **Verdict**, then **Top findings**, then **ATT&CK
  coverage**. Then work the **Findings** tab from critical down. Each card says why it
  matters and what to do next.
* Deleted and fileless binaries are copied out of `/proc/<pid>/exe` into `evidence/`
  automatically. **Do this before you kill anything**: once the process dies, that copy
  is gone.
* Your own ssh session is excluded from process findings (tagged `analyst-session`).
* Escalate immediately on any **critical**. Hidden PIDs, hidden kernel modules, an
  unpackaged `ld.so.preload` library or PAM module, or a dpkg checksum mismatch on a
  system binary mean the host's own tools are untrustworthy: switch to memory
  acquisition (AVML) and disk imaging, and stop working on the live box.
* **Preferred kit for live hosts:** `scripts/collect_case.sh` (target, no network) and
  `procsnap_analyze.py case.tar.gz --vt-key …` (analysis machine). The analyser adds
  geolocation and VirusTotal reputation for every public IP and executable hash.
  Lookups only, never uploads. Verify the archive's `.sha256` before analysing.
* **Disk image instead of a live host:** mount it read-only and run
  `procsnap.py triage --root /mnt/image`. The file-based checks all run; process,
  network and kernel checks need a live system.
* **After cleanup**, run again with `--compare case-1234/triage.json`. The Changes tab
  must show the findings as *resolved* and nothing new.

See [TRIAGE_CHECKS.md](TRIAGE_CHECKS.md) for what every check means and its usual
benign explanations.

---

## AD HOC — Running the collector without installing anything

The systemd service in Phase 0 is for standing fleet coverage. For live response you
usually want the opposite: copy one file to the host, run it for a bounded window,
leave nothing behind.

**Start it once, stop it when you're done** — the common case:

    sudo nohup ./procsnap.py collect -i 10m -o ./case-1234 --gzip >/dev/null 2>&1 &
    echo $! > ./case-1234/collector.pid

    # ... investigate, wait for the thing to recur ...

    sudo kill $(cat ./case-1234/collector.pid)
    tail -1 ./case-1234/*.jsonl        # confirms {"ev":"collector_stop", ...}

`--interval` takes a duration — `30s`, `10m`, `1h`; a bare number means seconds.
It traps both SIGINT (Ctrl+C) and SIGTERM, writes a `collector_stop` record, and exits
within 0.25s even if it is mid-way through a 10-minute sleep.

**Self-terminating window** (nothing left running if you get pulled away):

    sudo ./procsnap.py collect -i 10 --count 180 -o ./case-1234   # 30 min at 10s
    sudo timeout 30m ./procsnap.py collect -i 10 -o ./case-1234   # same, by clock

**A single snapshot** — `ps aux` + `netstat -tunap`, correlated, ~20ms:

    sudo ./procsnap.py once -o ./case-1234

**Nothing written to the suspect disk:**

    sudo ./procsnap.py once --stdout -o '' | ssh ir-box 'cat > host.jsonl'

**Live tail while collecting:**

    sudo ./procsnap.py collect -i 5 --stdout -o ./case-1234 \
      | jq -c 'select(.ev=="proc_start" and .baseline!=true) | {ts,comm,cmdline}'

> With `once` every record is `baseline`, so rarity analysis is meaningless —
> everything ran exactly once. Listener inventory, external destinations and heuristic
> flags still work. Use `timeline --baseline` to see the records. Two snapshots are the
> minimum for any delta.

---

## PHASE 0 — Preparation  (do this before you need it)

**0.1 Deploy to the fleet**

    sudo ./procsnap.py install-service --interval 10 --out /var/log/procsnap --retain-days 30
    sudo systemctl daemon-reload && sudo systemctl enable --now procsnap
    systemctl is-active procsnap

Interval guidance: 10s general fleet, 5s on crown-jewel hosts, 15-30s on
high-density/containerised boxes where the fd walk is expensive.

**0.2 Ship logs OFF the host.** Critical. An attacker with root deletes
`/var/log/procsnap/`. Nightly push, or filebeat/rsyslog tail of the JSONL:

    rsync -az /var/log/procsnap/ ir-collector:/evidence/$(hostname)/

**0.3 Build a golden baseline.** Run 48h on a known-good host of each role
(web, db, jump). Export and keep it:

    ./procsnap.py sqlite /var/log/procsnap -o baselines/web-role.db

This is what makes rarity analysis work — "rare on this host" is weak,
"never seen on any host of this role" is strong.

**0.4 Golden triage per role.** Triage a known-good host of each role and keep the
JSON. A later triage with `--compare baselines/web-role-triage.json` then shows exactly
what differs from a clean host of that role. That is the strongest signal on hosts with
lots of vendor software:

    sudo ./procsnap.py triage -o baselines/web-role --no-collect
    ./procsnap.py mkbaseline baselines/web-role*/triage.json -o baselines/web-role.json

Then every triage of that role can run with `--baseline baselines/web-role.json`. New
services and cron jobs, and any whose program path or hash changed, become findings.

**0.5 Record the tool's own hash** so its output is defensible later (every
`triage.json` also embeds the SHA-256 of the procsnap.py that produced it):

    sha256sum procsnap.py >> /evidence/tooling-manifest.txt

---

## PHASE 1 — Alert received (T+0)

**1.1 Do NOT log in and start poking yet.** Every command you run appears in the
data and contaminates the rarity analysis.

**1.2 Triage first** (see TRIAGE above). It takes about a minute, it is read-only apart
from the case folder, and it tells you whether the rest of this playbook is an
investigation or a confirmation.

**1.3 Mode A — pull the log, don't work on the host:**

    scp target:/var/log/procsnap/procsnap-*.jsonl* ./case-1234/

**1.4 Mode B — start collecting, and note the time:**

    sudo ./procsnap.py collect -i 5 -o /var/log/procsnap --gzip &
    date -u +%FT%TZ | tee case-1234/analyst-start.txt

Everything after that timestamp that is yours must be excluded from findings.
Record your own session PID/PPID so you can filter your subtree out.

**1.5 Preserve first, analyse second.**

    sha256sum case-1234/*.jsonl* > case-1234/HASHES.txt

The JSONL is the evidence artifact. Never edit it. All analysis works on a
derived `.db`, which is regenerable at any time.

---

## PHASE 2 — Collector analysis  (Tier 1, ~10 minutes)

**2.1 One-page overview scoped to the alert window:**

    ./procsnap.py report ./case-1234 --since '2026-08-24 03:00'

Read in this order: (a) Heuristic flags, (b) Listening sockets seen,
(c) External destinations by process, (d) Top parent -> child pairs.

**2.2 Rarity stack-rank — the highest-yield single query:**

    ./procsnap.py sqlite ./case-1234 -o case.db
    -- rare commands
    SELECT comm, COUNT(*) n, MIN(datetime(ts,'unixepoch','localtime')) first
    FROM procs WHERE ev='proc_start' AND baseline=0
    GROUP BY cmdline HAVING n<=3 ORDER BY n;

**2.3 Diff against the golden baseline** — anything present here and absent there:

    ATTACH 'baselines/web-role.db' AS base;
    SELECT DISTINCT comm, cmdline FROM procs
    WHERE ev='proc_start' AND cmdline NOT IN
      (SELECT cmdline FROM base.procs WHERE ev='proc_start');

**Tier-1 exit criteria.** Escalate to Tier 2 if any of: a heuristic flag fires,
a new external destination appears, a listener exists that isn't in the baseline,
or a service account spawned a shell. Otherwise close as benign with the report
attached.

---

## PHASE 3 — Investigation  (Tier 2/3)

**3.1 Anchor on a timestamp and expand around it:**

    ./procsnap.py timeline ./case-1234 --since '2026-08-24 03:12' --limit 300

**3.2 Reconstruct ancestry.** Each proc_start carries `pcomm`/`pcmdline`, so the
parent is known even if it already exited. Walk it upward to find patient zero —
typically ending at a web server, a cron, or an sshd session.

    SELECT datetime(ts,'unixepoch','localtime'), pid, ppid, pcomm, comm, cmdline
    FROM procs WHERE ev='proc_start' AND (pid=<PID> OR ppid=<PID>) ORDER BY ts;

**3.3 Attribute the network to the process:**

    ./procsnap.py conns ./case-1234 --external-only -v

**3.4 Beaconing / C2 check** (needs interval <= half the suspected beacon period):

    SELECT comm, raddr, rport, COUNT(*) hits, ROUND(AVG(gap),1) avg_gap,
           ROUND(MAX(gap)-MIN(gap),1) jitter
    FROM (SELECT comm, raddr, rport,
                 ts - LAG(ts) OVER (PARTITION BY raddr,rport ORDER BY ts) gap
          FROM socks WHERE ev='conn_open')
    WHERE gap IS NOT NULL GROUP BY 1,2,3 HAVING hits>=4 ORDER BY jitter;

**3.5 Persistence check.** Compare listeners and long-lived processes across
collector restarts — a `listen_open` that reappears after every reboot is a
persistence mechanism.

    SELECT laddr, lport, comm, COUNT(*) FROM socks
    WHERE ev='listen_open' AND baseline=1 GROUP BY 1,2,3;

**3.6 Fleet sweep.** Take the strongest indicator (cmdline substring, remote IP,
exe path) and grep every host's logs. This converts one finding into scope:

    grep -l '5.6.7.8' /evidence/*/procsnap-*.jsonl

---

## PHASE 4 — Containment

The data hands you the four containment inputs directly:

| From procsnap | Containment action |
|---|---|
| `pid` on the malicious proc_start | kill / freeze the process |
| `exe` path (+ `exe_deleted` flag) | quarantine binary, or dump from `/proc/<pid>/exe` **before** killing |
| `laddr:lport` from listen_open | firewall the listener |
| `raddr:rport` from conn_open | blackhole the C2, add to blocklist |

**Leave the collector running through containment.** Its output is your proof the
process actually stopped and the connection actually died — you will see the
`proc_exit` and `conn_close` events with timestamps.

If the exe is deleted (`exe_deleted: true`), recover it from `/proc/<pid>/exe`
before you kill the process — that is the only remaining copy.

---

## PHASE 5 — Evidence & reporting

1. Final hash + copy to the case store; keep the original JSONL and the triage case
   folder untouched (`HASHES.txt` covers the triage output).
2. Extract IoCs: external IPs, ports, exe paths, cmdline signatures, and the SHA-256 of
   every sample in the triage `evidence/` folder.
3. Feed IPs/domains to threat intel; feed cmdline patterns back into
   `SUSPECT_CMD` in `procsnap.py` so the next case flags it automatically.
4. Attach to the report: `triage.html` (print it to PDF for the case file), the
   `report` output, the annotated timeline extract, and the ancestry chain for
   patient zero.

---

## Known limits — state these in every report

* **Triage reads through the running kernel.** A kernel rootkit can hide from /proc.
  Hidden-PID, hidden-module and dpkg-checksum checks catch common rootkits, not
  careful ones. "No indicators" never proves the host is clean.
* **Poller, not a hook.** Processes that start and exit between two snapshots are
  never recorded. Absence of evidence is not evidence of absence. Pair with
  `auditd` (`-a always,exit -F arch=b64 -S execve`) where exec completeness matters.
* **Local logs are attacker-reachable.** Only off-box copies are trustworthy on a
  root-compromised host.
* **Analyst contamination.** Your own commands are in the data. Filter your session
  subtree before presenting rarity findings.
* **Requires root** for cmdline/exe and socket-to-PID attribution.
* **Beacon resolution** is bounded by the sample interval.
