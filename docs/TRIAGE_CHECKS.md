# Triage check reference

Every finding in a `triage.json` / `triage.html` carries a **check id** (the `check`
field). This page lists them all: what each one looks at, how severe it is, which
MITRE ATT&CK technique it maps to, and the usual benign explanation.

Severity scale:

| Severity | Meaning |
|---|---|
| **critical** | An indicator of compromise. Treat the host as compromised until explained. |
| **high** | Strongly suspicious. Needs an analyst decision before the case is closed. |
| **medium** | Unusual or risky configuration. Often legitimate; confirm it is expected. |
| **low** | Context. Worth a glance when hunting, rarely actionable alone. |
| **info** | Inventory notes (e.g. the list of unpackaged running binaries). |

The verdict follows the worst finding: any critical → *Indicators of compromise found*;
any high → *Suspicious activity*; any medium → *Review*; otherwise *No indicators found*.

"Unpackaged" means *not owned by any installed Debian package* (from
`/var/lib/dpkg/info/*.list`, usr-merge aware). On hosts without dpkg, the checks that
depend on ownership switch themselves off and say so under **Run info → Notes**.

---

## Processes (live only)

The analyst's own session (same session id as the triage process) is excluded and
marked `analyst-session`.

| Check | Severity | ATT&CK | Detects | Benign when |
|---|---|---|---|---|
| `memfd-exe` | critical | T1620 | Process whose executable is an anonymous memfd (`/memfd:...`) — fileless execution | Almost never; some sandboxes / JIT runtimes |
| `kthread-masquerade` | critical | T1036.004 | A user process named like a kernel thread (`[kworker/0:1]`, `ksoftirqd`...) that has a real executable | Never |
| `miner` | critical | T1496 | Miner names / pool URLs in comm, exe or arguments (xmrig, kinsing, stratum+tcp...) | Authorised mining |
| `reverse-shell` | critical / high | T1059.004 | Shell or netcat (critical) or interpreter (high) whose stdin/stdout is a **TCP/UDP** socket | inetd-style services |
| `exe-deleted` | high | T1070.004 | Binary deleted from disk while running and not package-owned. Copied out of `/proc/<pid>/exe` | Developer rebuilt a binary |
| `exe-replaced` | low | — | Running binary was replaced by a package upgrade (old copy in memory) | Restart pending after `apt upgrade` |
| `exe-world-writable` | high | T1105 | Executable running from `/tmp`, `/var/tmp`, `/dev/shm` | Installers, some CI jobs |
| `suspicious-cmdline` | high | T1059.004 | Command line matches download-and-execute, reverse shell, `base64 -d`, `/dev/tcp`, history wiping, miner patterns | Admin one-liners |
| `service-spawned-shell` | high | T1505.003, T1059.004 | Shell / netcat whose ancestry contains a web server, PHP-FPM, database, FTP or mail daemon, or that runs as `www-data`, `nobody`, `mysql`... | PHP `mail()` runs `sh -c sendmail` |
| `ld-preload-env` | high / low | T1574.006 | Process started with `LD_PRELOAD`. High if the library is unpackaged (it is collected) | jemalloc, eatmydata, faketime |
| `high-cpu-unpackaged` | medium | T1496 | Unpackaged binary using ≥70% CPU over the 1 s sample | Compilers, vendor agents |
| `ptraced` | medium / low | T1055.008 | Process being ptrace-attached (low when the tracer is gdb/strace/ltrace) | Debugging |
| `cwd-world-writable` | medium | — | Process whose working directory is a temp dir | Interactive users in /tmp |
| `bpf-unpackaged` | medium | T1205.002 | Unpackaged binary holding eBPF programs (BPFDoor-style backdoors, eBPF rootkits) | Observability agents |
| `inline-interpreter` | medium | T1059.004 | `python -c`, `perl -e`, `php -r` run by a service account | Health-check scripts |
| `hidden-pid` | critical | T1014 | PID that answers `kill(pid, 0)` but is missing from the `/proc` listing — a getdents-hooking rootkit. Default scan covers up to the highest visible PID + 131072; `--deep` covers all of `pid_max` | Never (threads are filtered out) |
| `unpackaged-running` | info | — | One summary listing every running executable not owned by a package | — |

## Network (live only)

| Check | Severity | ATT&CK | Detects |
|---|---|---|---|
| `listener-bad-exe` | critical | T1071 | A listening socket owned by a deleted, memfd or temp-dir binary |
| `listener-shell-tool` | high | T1059.004 | A shell, `nc`, `socat`, `telnet` or `openssl` listening — bind shell shape |
| `c2-candidate` | high | T1071 | External connection from a deleted / memfd / temp-dir binary |
| `raw-socket` | high / medium / low | T1040, T1205.002 | Packet (high) or raw (medium) socket held by an unexpected process. Sniffers (tcpdump, Suricata...) are low; DHCP clients and network daemons are ignored. BPFDoor never opens a listening port — this is how you see it |
| `promiscuous` | medium | T1040 | Interface in promiscuous mode that is not a bridge port |

Inventories: listeners, connections (external first), raw/packet sockets, interfaces.

## Kernel (live only)

| Check | Severity | ATT&CK | Detects |
|---|---|---|---|
| `hidden-module` | critical | T1014, T1547.006 | Module visible in `/sys/module` or `/proc/kallsyms` but missing from `/proc/modules` (Diamorphine, Reptile, PUMAKIT behaviour) |
| `rootkit-module-name` | critical | T1014 | Loaded module named like a known LKM / eBPF rootkit |
| `module-no-file` | high | T1547.006 | Loaded module with no `.ko` under `/lib/modules/$(uname -r)` |
| `module-unpackaged` | medium | T1547.006 | Loaded module whose file no package owns (DKMS modules under `updates/` or `extra/` are only tagged, not flagged) |
| `kernel-tainted` | high / medium / low | T1547.006 | Taint bits F (forced load), E (unsigned), O (out-of-tree). Non-security bits (soft lockup, warnings) are shown in Host facts only |

## Accounts, SSH, sudo, logins

| Check | Severity | ATT&CK | Detects |
|---|---|---|---|
| `uid0-account` | critical | T1136.001, T1078.003 | Any UID-0 account other than `root` |
| `passwd-hash` | high | T1136.001 | Password hash stored directly in `/etc/passwd` |
| `empty-password` | high | T1078.003 | Empty password field for a login-capable account |
| `service-account-shell` | high / low | T1078.003 | System account (UID 1–999) with a login shell — high if it also has a password |
| `duplicate-uid` | high | T1136.001 | Two accounts sharing a non-zero UID |
| `root-equivalent-group` | medium | T1078.003 | Member of `docker`, `lxd`, `disk` or `shadow` |
| `password-recent` | low | T1078.003 | Password set/changed within `--days` (also catches new accounts) |
| `ssh-key-nologin-user` | high | T1098.004 | `authorized_keys` entry for an account whose shell is nologin/false |
| `ssh-keys-recent` | medium | T1098.004 | `authorized_keys` file changed within `--days` |
| `ssh-authorized-keys2` | medium | T1098.004 | Keys in the deprecated, rarely reviewed `authorized_keys2` |
| `sshd-config` | high / medium / low | T1021.004, T1098.004 | `PermitEmptyPasswords yes` (high), `PermitRootLogin yes`, `AuthorizedKeysCommand` (medium), non-default `AuthorizedKeysFile` (low) |
| `sshd-dropin-recent` | low | T1021.004 | New unpackaged file in `sshd_config.d` |
| `sudo-no-auth` | high | T1548.003 | `Defaults !authenticate` |
| `sudo-env-keep-ld` | high | T1548.003, T1574.006 | sudo preserving `LD_PRELOAD` / `LD_LIBRARY_PATH` |
| `sudo-nopasswd-all` | medium | T1548.003 | `NOPASSWD: ALL` rule (common in cloud images — confirm the user) |
| `sudoers-dropin-recent` | medium | T1548.003 | Unpackaged `sudoers.d` file changed within `--days` |
| `bruteforce-success` | high | T1110, T1078.003 | Successful login from a source that also produced ≥20 failed logins (btmp + auth.log) |
| `service-account-login` | high | T1078.003 | A system account logged in interactively (wtmp / auth.log) |
| `root-password-login` | medium | T1021.004 | root logged in with a password from a public address |
| `useradd-event` | high / medium / low | T1136.001 | `useradd` in auth logs: high for UID 0, low for system users |
| `privileged-group-add` | high | T1078.003 | `usermod` adding someone to sudo/root/wheel/admin/docker/lxd/shadow |
| `session-service-account` | high | T1078.003 | A system account (www-data, nobody...) is logged in **right now** |
| `session-from-bruteforce-source` | high | T1110, T1078.003 | Someone is logged in now from a source that produced ≥20 failed logins |
| `session-no-utmp` | medium | T1070.002 | Live interactive SSH session (seen through its sshd process) with no utmp record: it was hidden from `who`/`w` |
| `session-notty` | low | T1021.004 | Live non-interactive SSH session (`ssh host cmd`, scp, sftp), which `who` never shows |

**Logged in now** (live): every current session cross-checked from three sources:
utmp (stale entries of dead processes dropped), systemd-logind
(`/run/systemd/sessions`) and sshd session processes (`sshd: user@pts/0`,
`sshd: user@notty`). Each session shows user, terminal, source, login time,
**session length**, **idle time**, which sources saw it, and what is running in it. The
analyst's own session is tagged `analyst-session`.
**Session history**: wtmp login/logout pairs (like `last`) with the duration of every
past session, and how it ended (logout, reboot, or still open).

Inventories: users, successful logins (user × source × method, with failure counts),
failed-login sources, account-change events, SSH keys with fingerprints, effective
sshd settings, sudoers rules.

## Persistence

| Check | Severity | ATT&CK | Detects |
|---|---|---|---|
| `ld-so-preload` | critical / medium | T1574.006, T1014 | Any library in `/etc/ld.so.preload` (critical if unpackaged; it is collected) — the userland-rootkit hook |
| `environment-ld` | high | T1574.006 | `LD_PRELOAD` / `LD_LIBRARY_PATH` in `/etc/environment` |
| `ld-so-conf-ww` | high | T1574.006 | Library search path in a temp dir or `/home` |
| `pam-module-unpackaged` | critical | T1556.003 | A PAM `.so` no package owns — the textbook SSH backdoor (master password + credential logging) |
| `pam-exec` | high | T1556.003 | `pam_exec` in any PAM stack (hands credentials to a script) |
| `pam-abs-module` | high | T1556.003 | PAM module loaded by absolute path from outside the package tree |
| `pam-permit-auth` | high | T1556.003 | `pam_permit` as `sufficient` (or `success=done`) in an auth stack — any password works. The stock Debian `auth required pam_permit.so` after `pam_deny` is **not** flagged |
| `cron-entry` | high | T1053.003 | cron line with a suspicious command, or executing from a temp dir |
| `cron-ww-ref` | medium | T1053.003 | cron line referencing a temp-dir path |
| `cron-service-account` | medium | T1053.003 | crontab for a system account (www-data, nobody...) |
| `cron-recent` | medium | T1053.003 | Unpackaged cron file changed within `--days` |
| `cron-script` / `cron-script-unpackaged` | high / medium / low | T1053.003 | Suspicious or unpackaged script in `cron.hourly/daily/weekly/monthly` |
| `at-job` | medium | T1053.002 | Any pending `at` job |
| `service-unit-modified` | high | T1543.002 | A package-installed unit file whose content no longer matches dpkg's MD5: someone edited a trusted service |
| `service-masquerade` | high | T1036.004, T1543.002 | Unpackaged unit named like a system service (`systemd-*`, `dbus-*`, `kworker*`..., or within a few characters of a packaged unit name) |
| `service-nondefault` | high / medium / low | T1543.002 | A non-default service (see below) running unpackaged programs: high from temp dirs or `/home`, medium if the unit or program changed within `--days`, low otherwise. Its programs are collected and hashed |
| `cron-nondefault` | medium / low | T1053.003 | A non-default cron job running an unpackaged program (medium if recent). The program is collected and hashed |
| `baseline-new-service` / `baseline-new-cron` | high / medium | T1543.002 / T1053.003 | With `--baseline DB`: a service or cron job no known-good host of this role has (high when it runs an unpackaged program) |
| `baseline-service-exec-path` | high | T1543.002 | With `--baseline DB`: same service, different program path |
| `baseline-service-exec-hash` / `baseline-cron-exec-hash` | high | T1543.002 / T1053.003 | With `--baseline DB`: same path, different binary (unpackaged programs only; packaged ones change on upgrades and dpkg verifies them) |
| `systemd-exec` | high | T1543.002 | Unit whose `Exec*=` is suspicious or runs from a temp dir |
| `systemd-home-exec` | high | T1543.002 | System unit running a binary from `/home` |
| `systemd-generator` | high | T1543.002 | Unpackaged systemd generator (runs at every boot before most logging) |
| `systemd-odd-link` | high | T1543.002 | `*.wants/` symlink enabling a unit outside the systemd directories |
| `systemd-user-unit` | medium | T1543.002 | Per-user unit in `~/.config/systemd/user` |
| `systemd-unit-recent` | medium | T1543.002, T1053.006 | Unpackaged unit / drop-in / timer changed within `--days` |
| `rc-local` | high / medium | T1037.004 | Commands in `/etc/rc.local` (high if suspicious or temp-dir) |
| `initd-script` | medium | T1037.004 | Unpackaged SysV init script |
| `motd-script` | high | T1546 | Unpackaged or suspicious `update-motd.d` script — runs as root on every SSH login |
| `apt-hook` | high | T1546 | `APT::Update::Pre-Invoke` / `DPkg::Post-Invoke` hooks in unpackaged files, or running suspicious commands — Debian-specific persistence |
| `udev-rule` | high | T1546.017 | Unpackaged udev rule with `RUN+=` |
| `network-hook` | medium | T1546 | Unpackaged NetworkManager dispatcher / if-up.d / dhclient hook |
| `xdg-autostart` | medium | T1547.013 | Unpackaged desktop autostart entry (system or per-user) |
| `modprobe-install` | high | T1547.006 | `install <module> <command>` in `modprobe.d` running something other than modprobe/true/false |
| `rootkit-autoload` | critical | T1547.006, T1014 | Module autoloaded from `modules-load.d` named like a rootkit |
| `shell-init` | high | T1546.004 / T1070.003 | Suspicious line in profile/bashrc files: callbacks, `LD_PRELOAD`, `PROMPT_COMMAND`, credential-stealing aliases (`sudo`, `su`, `ssh`, `passwd`), `trap DEBUG`, history suppression. Stock `alias ls=` is ignored |
| `profile-d-recent` | medium | T1546.004 | New unpackaged `/etc/profile.d` script |

### More attacker persistence (beyond cron and systemd)

| Check | Severity | ATT&CK | Detects |
|---|---|---|---|
| `ssh-rc` | high / medium | T1546, T1098.004 | `/etc/ssh/sshrc` or `~/.ssh/rc`: run by sshd on every login (high if unpackaged or suspicious) |
| `ssh-environment` | high / medium / low | T1546, T1574.006 | `~/.ssh/environment` (high with `PermitUserEnvironment` and `LD_*`/`PATH`) |
| `ssh-key-environment` | medium | T1098.004, T1574.006 | `environment="…"` option on an authorized key |
| `sshd-trust` | high / medium | T1098.004, T1556 | `TrustedUserCAKeys` (a CA that can mint logins), `AuthorizedPrincipalsCommand/File`, `ForceCommand`, `PermitUserEnvironment` |
| `nss-module-unpackaged` | critical | T1556 | `nsswitch.conf` loads an unpackaged `libnss_*.so` (loaded by sshd, login, every user lookup) |
| `sudo-plugin-unpackaged` | critical | T1548.003, T1556 | `sudo.conf` loads an unpackaged plugin |
| `polkit-rule` | high | T1548 | Unpackaged polkit rule / `.pkla` that returns YES (privileged actions without a password) |
| `webserver-module-unpackaged` | critical | T1505 | Apache `LoadModule` / nginx `load_module` of an unpackaged `.so` |
| `php-auto-prepend` | high | T1505.003 | `auto_prepend_file` / `auto_append_file` in php.ini, `.user.ini` or `.htaccess` |
| `lib-unpackaged` | high / medium | T1574.006 | Unpackaged shared library sitting in a system library directory (high when recent; collected) |
| `path-shadowing` | high / medium | T1574.007 | A file in `/usr/local/{s,}bin` with the same name as a packaged system command (high for sudo, ssh, ps, ls, passwd…) |
| `python-startup-hook` | high / medium / low | T1546.018 | Code-executing `*.pth` / `sitecustomize.py` / `usercustomize.py`: high if it decodes, opens sockets, runs processes, or if a packaged hook was modified; package-owned unmodified hooks are skipped |
| `git-config-exec` | high / medium | T1546 | `core.fsmonitor`, `core.pager`, `core.sshCommand`, `!` aliases or `core.hooksPath` in system/user git config running suspicious programs |
| `logrotate-script` | high / medium | T1053.003, T1546 | `postrotate`/`prerotate`/`firstaction`/`lastaction` scripts that are suspicious, run unpackaged programs, or live in unpackaged/modified logrotate files |
| `boot-init-override` | critical | T1037, T1574.006 | `init=`/`rdinit=` or `LD_PRELOAD` on the kernel command line (`/proc/cmdline`, `/etc/default/grub`, `grub.cfg`) |
| `initramfs-hook` | high | T1037 | Unpackaged initramfs-tools / dracut hook or script (runs at every boot, before the root fs) |
| `inittab` | high | T1037 | Suspicious respawn/boot entry in `/etc/inittab` |
| `systemd-linger` | medium / low | T1543.002 | User lingering (user units start at boot without a login); medium when that user has units |
| `systemd-env-preload` | critical | T1574.006 | `DefaultEnvironment`/`ManagerEnvironment` with `LD_PRELOAD` in systemd's own config |
| `anacron` | high / medium | T1053.003 | anacron job running a suspicious or unpackaged program |
| `incron` | high / medium | T1546 | incron file-event watch (runs a command when a file changes) |
| `tcpwrappers-spawn` | high | T1546 | `spawn` / `twist` in `/etc/hosts.allow` / `hosts.deny` |
| `dpkg-hook` | high | T1546 | dpkg `pre-invoke` / `post-invoke` in an unpackaged `dpkg.cfg.d` file |
| `skel-or-completion` | high / medium | T1546.004 | Suspicious content in `/etc/skel` (copied into every new account) or bash-completion scripts (sourced by every shell) |
| `container-escape-autostart` | high | T1543.005, T1611 | Docker container with `restart=always/unless-stopped` **and** host access (privileged, `/`/`/etc`/`docker.sock` mounted, host PID ns, `SYS_ADMIN`) |
| `container-host-access` | medium | T1611 | Same host access without auto-restart |
| `k8s-static-pod` | medium | T1543.005 | Recently changed Kubernetes static-pod manifest |
| `immutable-file` | high / medium / low | T1222.002 | `chattr +i` / `+a` on cron files, units, keys, passwd/shadow, rc files, binaries: attackers lock persistence so cleanup silently fails |

Systemd transient units (`/run/systemd/transient`, created by `systemd-run`) are now
part of the service view. Inventories: `persistence_more` (every hook found, flagged or
not), `containers`, `immutable`. Docker containers are read straight from
`/var/lib/docker/containers`, so this works offline and without the docker CLI.

### Default vs non-default services and cron jobs

For every **effective** unit (respecting `/etc` > `/run` > `/usr/lib` precedence and
drop-ins), ProcSnap resolves the programs it really runs. It unwraps `sh -c`, `nohup`,
`env`, `sudo -u`, `flock`, `nice`, `timeout`, `python script.py` and `cd x && y`,
resolves bare names via `PATH`, and records each program's path, owning package and
SHA-256. A service is **default** only if:

1. a package installed its unit file,
2. the file still matches dpkg's MD5,
3. no unpackaged drop-in changes it, and
4. every program it runs is package-owned.

Anything else lands in **Non-default services** with the reason (new unit, overrides
a packaged unit, unit edited, drop-in changes ExecStart, runs an unpackaged program),
whether it is enabled, and the PID and executable it is running as (from its cgroup).

Cron jobs work the same way: a job is default only if it lives in a package-installed
cron file and runs package-owned programs. User crontabs are never default. Each job's
program path, package and SHA-256 are recorded, and unpackaged programs are collected
into `evidence/`. `procsnap_analyze.py` looks their hashes up on VirusTotal
(non-default ones first) and adds an **exec VT** column.

**Baseline DB.** The reference above is the host's own dpkg database, which is exact
for its OS version. To also compare against *your* known-good hosts:

```bash
procsnap.py mkbaseline clean-web1/triage.json clean-web2/triage.json -o web-role.json
procsnap.py triage --baseline web-role.json            # or: procsnap_analyze.py case.tgz --baseline web-role.json
```

## Logs and history

| Check | Severity | ATT&CK | Detects |
|---|---|---|---|
| `history-devnull` | high | T1070.003 | Shell history symlinked to `/dev/null` |
| `history-suspicious` | high | T1059.004 | Suspicious commands in any user's shell history (one finding per file, lines listed) |
| `log-devnull` | high | T1070.002 | A key log symlinked to `/dev/null` |
| `log-empty` | medium | T1070.002 | wtmp / lastlog / auth.log / syslog empty on a host up for more than a day |

## Integrity (Debian package database)

| Check | Severity | ATT&CK | Detects |
|---|---|---|---|
| `dpkg-mismatch` | critical | T1554 | File whose MD5 differs from the one dpkg recorded. Default scope: `bin`/`sbin`, PAM modules, OpenSSH helpers, `/usr/libexec` and core libraries (libc, libpam, libkeyutils (Ebury), libaudit, libcrypt, libssl...). `--deep` verifies every packaged file. Diverted files are skipped |
| `conffile-modified` | medium / low | T1556.003 / T1546 | Security-relevant config file (PAM, ld.so, nsswitch, motd, sudoers) changed from the package default (from `/var/lib/dpkg/status`) |
| `bin-unpackaged` | high / medium | T1036.005 | Unpackaged regular file in `/usr/bin`, `/usr/sbin` (high when recent; collected) |
| `bin-symlink-ww` | high | T1036.005 | Symlink in a system bin dir pointing into a temp dir or `/home` |

## Filesystem sweep

Walks the interesting trees (`/tmp`, `/var/tmp`, `/dev/shm`, `/etc`, `/root`, `/home`,
`/usr`, `/opt`, `/srv`, `/var/www`, `/var/spool`, `/var/lib`, `/boot`) within
`--walk-budget` seconds; `--deep` walks `/`. Pseudo filesystems, container storage and
large database directories are skipped; the case directory itself is excluded.

| Check | Severity | ATT&CK | Detects |
|---|---|---|---|
| `suid-unpackaged` | critical / high | T1548.001 | Unpackaged SUID/SGID file (critical in temp dirs or `/home`) |
| `caps-unpackaged` | high / medium | T1548.001 | Unpackaged executable with file capabilities (high for setuid, dac_override, sys_admin, sys_ptrace...) |
| `dropped-file` | high / medium | T1105 | Executable ELF directly in a temp dir, anything executable in `/dev/shm` |
| `temp-tree` | low | T1105 | Scripts / shared libraries nested inside a folder in a temp dir — usually an unpacked project or virtualenv, grouped into one finding per folder |
| `hidden-dir-tmp` | medium | T1564.001 | Directory in a temp dir named `...`, `. `, or with leading/trailing spaces |
| `webshell` | high | T1505.003 | PHP/JSP/ASPX/CGI file under a web root with eval-of-request, decode-and-eval, `preg_replace /e`, or a known shell family marker |

Inventories: SUID/SGID files, files with capabilities, temp-dir executables, web-shell
hits, and **system files changed within `--days`** (ctime-based, so `touch`
timestomping does not hide them; `mtime<ctime` on an unpackaged file is tagged).
