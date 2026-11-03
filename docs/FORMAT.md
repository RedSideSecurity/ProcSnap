# Output formats

## `triage.json`

One JSON object per triage run.

```jsonc
{
  "tool": "procsnap", "kind": "triage", "version": "2.0.0",
  "started": 1793686995.12,            // epoch seconds (UTC)
  "duration_s": 46.1,
  "host": {                             // facts collected by the "host" check
    "hostname": "web01", "os": "Debian GNU/Linux 12 (bookworm)", "kernel": "6.1.0-26-amd64",
    "arch": "x86_64", "mode": "live",   // or "offline image at /mnt/web01"
    "boot": 1793452265, "uptime_s": 233080, "tainted": 0, "timezone": "UTC +0000",
    "root_privileges": true, "dpkg_packages": 1493,
    "dpkg_files_verified": 1684, "dpkg_scope": "binaries, PAM, sshd helpers, core libraries",
    "pid_scan": "1..384737", "files_swept": 336789, "wtmp_records": 1142
  },
  "verdict": {"level": "compromised", "text": "Indicators of compromise found"},
  //          level: compromised | suspicious | review | clean
  "counts": {"critical": 4, "high": 16, "medium": 3, "low": 3, "info": 1},
  "options": {"root": "/", "days": 7, "deep": false, "collect": true, "walk_budget": 240},
  "findings": [ /* see below, sorted most severe first */ ],
  "inventory": { /* name -> table, see below */ },
  "evidence": [
    {"path": "/proc/254762/exe", "size": 35336, "why": "fileless process",
     "sha256": "…", "saved": "evidence/3f1c…_memfd-254762.sample"}
  ],
  "errors": [ {"check": "logins", "error": "no /var/log/auth.log* - journald-only host? …"} ],
  "timings": {"processes": 5.6, "package integrity": 25.4, "filesystem sweep": 9.1, …},
  "mitre": {"T1620": {"name": "Reflective Code Loading", "tactic": "Defense Evasion"}, …},
  "tactics": ["Execution", "Persistence", …],
  "self": {"sha256": "<sha256 of procsnap.py>", "pid": 254790, "argv": ["procsnap.py", "triage"]}
}
```

### Finding

```jsonc
{
  "id": "9b1f0c2e7a44",          // stable fingerprint: check + identity key (no PIDs)
  "sev": "critical",             // critical | high | medium | low | info
  "cat": "process",              // process network kernel persistence accounts logs integrity filesystem
  "check": "memfd-exe",          // see docs/TRIAGE_CHECKS.md
  "title": "Fileless process 3 (254762) runs from memory (/memfd:x)",
  "mitre": ["T1620"],
  "why": "The executable lives only in an anonymous memfd …",
  "fix": "Dump /proc/<pid>/exe and memory before killing it.",
  "evidence": {"pid": 254762, "user": "root", "exe": "/memfd:x", "cmdline": "…",
               "parent": "bash (254700)", "started": "2026-11-03 06:09:41", "sha256": "…"}
}
```

`id` does not include PIDs or timestamps. The same problem found on two runs gets the
same id, which is what `triage-diff` and `--compare` use to report new and resolved
findings.

### Inventory table

```jsonc
"systemd": {
  "title": "systemd units", "cat": "persistence",
  "cols": ["unit", "scope", "path", "package", "exec", "changed", "flags"],
  "rows": [["dbus-org.service", "system", "/etc/systemd/system/dbus-org.service", "",
            "/dev/shm/dbus-org --daemon", "2026-11-03 06:16:37", ["ww-exec", "unpackaged"]]],
  "key": [0, 1, 2, 4],          // columns that identify a row when diffing two runs
  "note": ""
}
```

A column named `flags` holds a list of short tags. The report highlights rows whose
flags include anything other than the context tags `external`, `recent`, `unpackaged`,
`dkms` and `analyst-session`.

Inventory names: `processes`, `listeners`, `connections`, `raw_sockets`, `interfaces`,
`modules`, `bpf_pins`, `users`, `ssh_keys`, `sshd_config`, `sudoers`, `pam`,
`ld_so_conf`, `services`, `services_nondefault`, `cron`, `cron_nondefault`, `at_jobs`,
`systemd` (raw unit files), `persistence_more`, `containers`, `immutable`, `autostart`, `shell_init`, `history`,
`sessions`, `session_history`, `logins`, `failed_logins`, `account_events`, `logfiles`, `dpkg_verify`, `conffiles`,
`bin_unpackaged`, `suid`, `caps`, `dropped`, `webshells`, `recent_changes`.

## Enriched triage (`procsnap_analyze.py`)

`triage.enriched.json` is a `triage.json` with these additions:

- `intel`: `{generated, geo_provider, virustotal, public_ips, hashes, countries:
  [{cc, country, ips}], vt_files: {looked_up, malicious, unknown}, vt_ips: {looked_up,
  malicious}, notes, case_meta}`
- findings with `cat: "intel"`: `vt-file`, `vt-ip`, `vt-unknown`
- inventories `intel_vt` (file, sha256, detections, malicious, label, first seen,
  seen as, virustotal, flags) and `intel_geo` (ip, country, city, asn, organisation,
  VT, seen as, virustotal, flags)
- `location` and `ip VT` columns appended to `connections`, `logins` and
  `failed_logins`; `exe VT` appended to `connections` and `listeners` (`N/M [label]`,
  `not in VT`, `dpkg-verified` or `not looked up`); `virustotal` appended to
  `processes`
- `counts`, `verdict` and `mitre` recomputed

`intel.json` holds the raw provider answers. The API key is never written anywhere.

## Baseline DB (`procsnap.py mkbaseline`)

```jsonc
{"kind": "procsnap-baseline", "version": 1, "created": 1793690000,
 "hosts": [{"hostname": "web1", "os": "Debian GNU/Linux 12", "triaged": 1793680000, "verdict": "clean"}],
 "services": {"system:nginx.service": {"exec_paths": ["/usr/sbin/nginx"],
                                       "exec_sha256": ["…"], "default": ["yes"]}},
 "cron": {"/etc/cron.d/certbot|root test -x /usr/bin/certbot … certbot -q renew":
              {"exec_paths": ["/usr/bin/certbot"], "exec_sha256": ["…"]}}}
```

User crontabs are keyed as `crontab:<user>|<command>`, so the same job matches across
hosts. When a triage is checked against a DB, `res["baseline"]["db"]` records which
DB was used and how many differences it produced.

## Collector JSONL

`procsnap collect` writes one file per day, `procsnap-YYYYMMDD.jsonl[.gz]`, with one
JSON object per line. Every line has `ts` (epoch seconds) and `ev`:

| `ev` | When | Key fields |
|---|---|---|
| `collector_start` | collector starts | host, kernel, boot, interval, root, version |
| `proc_start` | a process is seen for the first time | pid, ppid, user, comm, cmdline, exe, exe_deleted, cwd, sid, tty, rss_kb, cpu_s, cgroup, start, pcomm, pcmdline, baseline, sha256 |
| `exe_deleted` | a running process's binary disappears from disk | pid, comm, cmdline, exe, start |
| `exe_hash` | an executable's SHA-256, computed in the idle time after its `proc_start` (new binaries only; known ones carry `sha256` on `proc_start` itself) | pid, start, comm, exe, sha256 |
| `proc_exit` | a process is gone | pid, comm, cmdline, lifetime_s, cpu_s, rss_kb_peak |
| `listen_open` / `listen_close` | listening socket appears / disappears | proto, laddr, lport, pid, comm, user, duration_s |
| `conn_open` / `conn_close` | connection appears / disappears | proto, laddr, lport, raddr, rport, state, pid, comm, dir (outbound/inbound, on open), duration_s |
| `inventory` | every `--full-every` snapshots | full procs / listen / conns lists (resync point) |
| `heartbeat` | every snapshot | n, nproc, nlisten, nconn, scan_ms |
| `collector_stop` | SIGINT / SIGTERM / `--count` reached | snapshots |

`baseline: true` marks entities that already existed in the first snapshot of a
collector session. A new `collector_start` resets the delta chain, so logs from cron'd
`once` runs and from reboots reconstruct correctly.
