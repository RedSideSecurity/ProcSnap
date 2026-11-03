# Security policy

ProcSnap is an incident-response tool that runs as root on hosts that may already be
compromised, and its reports are opened by analysts. We take both directions seriously:

* **On the target**, the tool only reads, apart from writing its own case folder.
  It never executes binaries it finds, and it copies suspicious files as read-only
  `*.sample` files with no execute bit.
* **In the report**, every value from the host is treated as attacker-controlled: it
  is embedded as escaped JSON and rendered with `textContent` only. Reports load
  nothing from the network.

## Reporting a vulnerability

Please report security issues privately via GitHub's *Report a vulnerability*
(Security → Advisories) on this repository, rather than in a public issue. Include
the version (`procsnap.py --version`), and a sample `triage.json` or JSONL line if the
issue is in the report renderer.
