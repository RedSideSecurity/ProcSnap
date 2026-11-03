# Changelog

## 2.0.0 — 2026-11-03

### Added
- **`triage`**: one-shot compromise assessment of a live Debian/Ubuntu host. About
  130 finding types across processes, network, kernel, accounts, SSH, sudo, PAM, dynamic
  linker, cron/at, systemd, other autostarts, shell init, history, logins, log
  integrity, dpkg package integrity and a filesystem sweep. Every finding has a
  severity, a MITRE ATT&CK mapping, an explanation and evidence. See
  `docs/TRIAGE_CHECKS.md`.
- Case folder output: `triage.json`, `triage.html`, `evidence/` (read-only
  `*.sample` copies, including binaries recovered from `/proc/<pid>/exe`) and
  `HASHES.txt`.
- `triage --root /mnt/image`: dead-box triage of a mounted disk image.
- `triage --compare old.json` and `triage-diff`: new / resolved findings and
  inventory changes against an earlier run or a golden host of the same role.
- Hidden-PID brute force, hidden kernel module detection (`/sys/module` and
  `kallsyms` against `/proc/modules`), dpkg MD5 verification of binaries, PAM modules
  and core libraries, and modified-conffile detection.
- New triage HTML report: verdict, severity tiles, ATT&CK coverage, filterable
  findings, process tree, inventories, evidence, changes and run info. Light/dark,
  print-to-PDF, fully offline.
- Collector: new `exe_deleted` event when a running process's binary is removed
  (previously missed if the process was first seen before the deletion).
- Tests: offline fixture suite (`tests/test_triage.py`), live attack simulation
  (`tests/live_attack_sim.sh`), verifying collector self-test
  (`tests/collector_selftest.sh`).

- **Target/analysis split:** `scripts/collect_case.sh` runs on the suspect host
  (triage plus an optional watch period, packaged as `case.tar.gz` plus `.sha256`, no
  network). `procsnap_analyze.py` runs on the analysis machine.
- **Threat-intel enrichment** in `procsnap_analyze.py`: geolocation and ASN of public
  IPs (ip-api.com or ipinfo), and VirusTotal reputation of executable hashes and
  public IPs (lookups only, rate-limited, cached). Detections become findings. New
  Threat intel report tab, plus geo/VT columns in the connection, login and process
  tables.
- SHA-256 of every running process's executable (triage `processes` table) and of
  each new process's binary in the collector (`proc_start.sha256`; `--no-hash` to
  disable).

- **Sessions:** who is logged in now (utmp + systemd-logind + sshd session processes,
  cross-checked) with session length, idle time and running processes; past session
  durations from wtmp login/logout pairs; findings for service-account sessions,
  sessions from brute-force sources, sessions hidden from utmp, and non-interactive
  SSH sessions. A "Logged in now" card on the report overview, plus a terminal summary
  line.

- **Network attribution:** every connection carries direction (outbound/inbound),
  process, PID, user, executable, command line, parent, package and executable
  SHA-256 (listeners too). The collector records direction on `conn_open`. The
  analyser adds separate location, IP VT and executable VT columns, and looks up
  binaries that own external connections on VirusTotal first. The report puts the
  analyst columns first and shortens hashes (copy button for the full value).
- Shared sockets (systemd socket activation) are credited to the real service, not
  PID 1.

- **Default vs non-default services and cron jobs:** effective units (precedence and
  drop-ins) and cron jobs are judged against the dpkg database (package-installed,
  unit unmodified per MD5, programs package-owned). The real programs are resolved
  (sh -c, nohup, sudo, env, flock, interpreters...) with path, package and SHA-256;
  unpackaged ones are collected. New `services` / `services_nondefault` /
  `cron_nondefault` tables, plus enabled state and running PID/exe from cgroups.
  Findings `service-unit-modified`, `service-masquerade`, `service-nondefault`,
  `cron-nondefault`.
- **Baseline DB:** `procsnap.py mkbaseline` builds a DB of known-good services and
  cron jobs with program paths and hashes from clean triages; `--baseline` (triage
  or analyser) flags new entries and changed program paths or hashes.
- The analyser looks up service and cron program hashes on VirusTotal (non-default
  first) and adds an `exec VT` column.

- **More attacker persistence:** SSH login hooks and trust anchors, NSS modules,
  sudo plugins, polkit rules, web-server modules, PHP auto_prepend_file, unpackaged
  system libraries, PATH shadowing, Python startup hooks, git config hooks,
  logrotate scripts, kernel `init=`, initramfs hooks, inittab, systemd lingering and
  environment, transient units, anacron, incron, tcp-wrappers spawn, dpkg hooks,
  /etc/skel and bash-completion, Docker containers (read offline from
  /var/lib/docker), Kubernetes static pods, and `chattr +i` locked files. About 30
  new checks with ATT&CK mappings.

- Snapshot deep links in the timeline report (`timeline.html#snaps=1,12`), README
  rewritten (problem statement, full command reference, snapshot-chain explanation),
  screenshots from a synthetic demo host (`docs/demo/plant_demo_host.sh`).
- GitHub Actions CI: lint and unit tests on Python 3.8–3.12, plus a live job as root
  (attack simulation, collector self-test, full triage, collect → analyse flow).
- README screenshots in the reports' dark theme.

### Fixed
- Collector: hashing executables inside the snapshot stalled the first snapshot for
  ~16 s on a cold cache, so the collector was blind at start. Binaries are now hashed
  in the idle time between snapshots, in 1 MB steps (a 500 MB binary never delays a
  snapshot), and reported as `exe_hash` events. Each hash is bound to the file's
  device/inode/size/mtime, so a recycled PID never inherits another binary's hash.
- `collect_case.sh` wrote the archive's full path into the `.sha256` file, so
  `sha256sum -c` failed once the case was copied to the analysis machine. It now records
  the bare file name.
- `tests/live_attack_sim.sh` uses per-run paths and ports, so concurrent runs no
  longer delete each other's plants.
- Independent review fixes:
  - `collect_case.sh` no longer deletes the case when packaging fails, and exits
    non-zero on packaging or triage failure. It never runs `procsnap.py` from the
    current directory, JSON-escapes host data, and validates option values.
  - Console output is sanitised: host data can no longer inject terminal escape
    sequences.
  - Analyser: only strictly valid SHA-256s and normalised public IPs reach lookup
    URLs; non-JSON or partial API answers keep the results gathered so far (the cache
    is always saved); corrupt `triage.json` and collector lines are handled cleanly.
  - Archive extraction keeps leading-dot names, tolerates duplicate members, and
    caps the expanded size (decompression bombs).
  - Report placeholders are filled in a single pass.
  - dpkg-diverted files and the Ubuntu-minimal MOTD artefact (containers and VMs,
    content-checked) are no longer reported.
  - `install-service` quotes paths and warns when the script is not root-owned.
  - Tests skip cleanly without `chattr` or `nc`.
- **Security:** the HTML reports embedded host data with `json.dumps` inside a
  `<script>` block. A process command line containing `</script>` could execute
  script in the analyst's browser. Data is now escaped (`<` etc.) and
  placeholders are filled before the data.
- Reports no longer load Google Fonts; they are now fully offline (system font
  stacks).
- Collector logs: a truncated `.gz` (still being written, or cut by `kill -9`) no
  longer crashes the analysis commands.
- Inline interpreters (`python -c`, `perl -e`) moved to a separate low-severity tag
  instead of `suspicious-cmdline`.
- Reading `/proc/sys/*` with one large `read()` fails with ENOMEM. Reads are now
  chunked.

## 1.0 — 2026-08-24
- Initial collector (`collect`, `once`, `install-service`), analysis commands
  (`report`, `timeline`, `procs`, `conns`, `snapshots`, `show`, `diff`, `sqlite`),
  the timeline HTML report and the IR playbook.
