#!/usr/bin/env python3
"""
Tests for procsnap_analyze.py against a local mock of the VirusTotal v3 and
ip-api.com APIs (no network, no API key needed).

    python3 -m unittest discover -s tests -v
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, HERE)
import procsnap_analyze as an   # noqa: E402
import test_triage as tt        # noqa: E402

KEY = "test-key-0123456789"
MAL = "a" * 64          # 41/72 engines, labelled
CLEAN = "b" * 64        # 0/72
UNKNOWN = "c" * 64      # 404 at VT
BAD_IP = "45.9.148.99"  # 12/94 engines - answered only by the local mock below; no claim
                        # is made about the real owner of this address
GOOD_IP = "8.8.8.8"


class Mock(BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):                                   # ip-api batch
        Mock.hits.append(self.path)
        ips = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        geo = {BAD_IP: ("Netherlands", "NL", "AS64500 Example Hosting (mock)", True),
               GOOD_IP: ("United States", "US", "AS15169 Google LLC", True)}
        out = []
        for ip in ips:
            c, cc, asn, host = geo.get(ip, ("Germany", "DE", "AS24940 Hetzner", True))
            out.append({"status": "success", "query": ip, "country": c, "countryCode": cc,
                        "city": "X", "as": asn, "org": asn.split(" ", 1)[1], "isp": "isp",
                        "hosting": host, "proxy": False})
        self._send(200, out)

    def do_GET(self):                                    # VirusTotal v3
        Mock.hits.append(self.path)
        if self.headers.get("x-apikey") != KEY:
            return self._send(401, {"error": {"code": "WrongCredentialsError"}})
        kind, _, obj = self.path.strip("/").partition("/")
        if kind == "files":
            if obj == MAL:
                return self._send(200, {"data": {"attributes": {
                    "last_analysis_stats": {"malicious": 41, "suspicious": 1, "undetected": 30,
                                            "harmless": 0},
                    "popular_threat_classification": {"suggested_threat_label": "trojan.xorddos/linux"},
                    "meaningful_name": "kworkerd", "names": ["kworkerd", "x86"],
                    "first_submission_date": 1700000000}}})
            if obj == CLEAN:
                return self._send(200, {"data": {"attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 72,
                                            "harmless": 0}}}})
            return self._send(404, {"error": {"code": "NotFoundError"}})
        if kind == "ip_addresses":
            # GOOD_IP mimics real 8.8.8.8 data: one lone engine, reputation +564
            mal = 12 if obj == BAD_IP else 1 if obj == GOOD_IP else 0
            return self._send(200, {"data": {"attributes": {
                "last_analysis_stats": {"malicious": mal, "suspicious": 0, "undetected": 30,
                                        "harmless": 52},
                "reputation": -40 if obj == BAD_IP else 564,
                "as_owner": "Example Hosting (mock)" if mal else "GOOGLE", "country": "NL" if mal else "US"}}})
        self._send(404, {})


def synthetic_case(tmp):
    """A triage.json shaped like a live run: processes with hashes + connections."""
    root = tt.build_fixture(os.path.join(tmp, "rootfs"))
    case = os.path.join(tmp, "case-src", "triage")
    subprocess.run([sys.executable, os.path.join(REPO, "procsnap.py"), "triage", "--root", root,
                    "-o", case, "-q", "--no-html"], check=True, capture_output=True)
    p = os.path.join(case, "triage.json")
    with open(p) as fh:
        res = json.load(fh)
    res["inventory"]["processes"] = {
        "title": "Running processes", "cat": "process", "key": [2, 3, 4, 5],
        "cols": ["pid", "ppid", "user", "comm", "exe", "cmdline", "started", "cpu%", "rss_kb",
                 "package", "flags", "sha256"],
        "rows": [[4242, 1, "root", "kworkerd", "/usr/bin/kworkerd", "kworkerd", "x", 0, 1, "", [], MAL],
                 [4243, 1, "root", "agent", "/opt/agent/agent", "agent", "x", 0, 1, "", [], UNKNOWN],
                 [1, 0, "root", "systemd", "/usr/lib/systemd/systemd", "/sbin/init", "x", 0, 1,
                  "systemd", [], CLEAN]]}
    res["inventory"]["connections"] = {
        "title": "Network connections", "cat": "network", "key": [0, 2, 3, 6],
        "cols": ["proto", "direction", "local", "remote", "rport", "state", "pid", "process",
                 "user", "exe", "cmdline", "parent", "package", "sha256", "flags"],
        "rows": [["tcp", "outbound", "10.0.0.5:40112", BAD_IP, 443, "ESTABLISHED", 4242, "kworkerd",
                  "root", "/usr/bin/kworkerd", "kworkerd", "systemd (1)", "", MAL, ["external"]],
                 ["tcp", "outbound", "10.0.0.5:40113", GOOD_IP, 53, "ESTABLISHED", 700, "resolved",
                  "systemd-resolve", "/usr/lib/systemd/systemd-resolved", "", "systemd (1)",
                  "systemd", CLEAN, ["external"]],
                 ["tcp", "inbound", "10.0.0.5:22", "10.0.0.9", 51000, "ESTABLISHED", 900, "sshd",
                  "root", "/usr/sbin/sshd", "sshd: root", "sshd (800)", "openssh-server", "", []]]}
    with open(p, "w") as fh:
        json.dump(res, fh)
    with open(os.path.join(tmp, "case-src", "case.json"), "w") as fh:
        json.dump({"tool": "procsnap", "kind": "case", "host": "fixture-web01"}, fh)
    arc = os.path.join(tmp, "procsnap-fixture-web01-20261103T000000Z.tar.gz")
    with tarfile.open(arc, "w:gz") as tf:
        tf.add(os.path.join(tmp, "case-src"), arcname="procsnap-fixture-web01-20261103T000000Z")
    return arc


class Analyze(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Mock)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{cls.srv.server_port}"
        cls.tmp = tempfile.mkdtemp(prefix="procsnap-an-")
        cls.env = dict(os.environ, PROCSNAP_VT_URL=base, PROCSNAP_IPAPI_URL=base + "/batch",
                       PROCSNAP_CACHE=os.path.join(cls.tmp, "cache"))
        cls.env.pop("VT_API_KEY", None)
        cls.arc = synthetic_case(cls.tmp)
        cls.out = os.path.join(cls.tmp, "analysis")
        Mock.hits.clear()
        cls.run1 = cls.analyse("--vt-key", KEY, "--vt-rate", "6000")
        cls.hits1 = list(Mock.hits)
        with open(os.path.join(cls.out, "triage.enriched.json")) as fh:
            cls.res = json.load(fh)

    @classmethod
    def analyse(cls, *args):
        p = subprocess.run([sys.executable, os.path.join(REPO, "procsnap_analyze.py"), cls.arc,
                            "-o", cls.out, "-q", *args], env=cls.env, capture_output=True,
                           text=True, timeout=120)
        if p.returncode:
            raise RuntimeError(p.stdout + p.stderr)
        return p.stdout + p.stderr

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def by(self, check):
        return [f for f in self.res["findings"] if f["check"] == check]

    def test_vt_file_detection(self):
        f = self.by("vt-file")
        self.assertEqual(len(f), 1, f)
        self.assertEqual(f[0]["sev"], "critical")
        self.assertIn("41/72", f[0]["title"])
        self.assertIn("trojan.xorddos", f[0]["title"])
        self.assertEqual(f[0]["evidence"]["virustotal"],
                         f"https://www.virustotal.com/gui/file/{MAL}")

    def test_vt_unknown_reported(self):
        f = self.by("vt-unknown")
        self.assertEqual(len(f), 1)
        self.assertIn("/opt/agent/agent", f[0]["evidence"]["files"])

    def test_packaged_hash_not_sent_by_default(self):
        self.assertFalse(any(CLEAN in h for h in self.hits1), "packaged binary was looked up")

    def test_vt_ip_detection_and_geo(self):
        f = self.by("vt-ip")
        self.assertEqual(len(f), 1, [x["title"] for x in f])   # 8.8.8.8's lone hit = noise
        self.assertEqual(f[0]["sev"], "critical")          # live connection + 12 engines
        self.assertIn(BAD_IP, f[0]["title"])
        conns = self.res["inventory"]["connections"]
        c = conns["cols"].index
        self.assertEqual(conns["cols"][-3:], ["location", "ip VT", "exe VT"])
        row = {r[c("remote")]: r for r in conns["rows"]}
        self.assertIn("NL", row[BAD_IP][c("location")])
        self.assertTrue(row[BAD_IP][c("ip VT")].startswith("12/"))
        self.assertTrue(row[BAD_IP][c("exe VT")].startswith("41/72 trojan.xorddos"))
        self.assertIn("vt-malicious", row[BAD_IP][c("flags")])
        self.assertEqual(row[GOOD_IP][c("exe VT")], "dpkg-verified")
        self.assertEqual(row["10.0.0.9"][c("location")], "private")   # never looked up
        self.assertEqual(row["10.0.0.9"][c("direction")], "inbound")
        self.assertFalse(any("10.0.0.9" in h for h in self.hits1))

    def test_verdict_and_tables(self):
        self.assertEqual(self.res["verdict"]["level"], "compromised")
        self.assertIn("intel_vt", self.res["inventory"])
        self.assertIn("intel_geo", self.res["inventory"])
        procs = self.res["inventory"]["processes"]
        self.assertEqual(procs["cols"][-1], "virustotal")
        self.assertIn("vt-malicious", procs["rows"][0][10])
        self.assertEqual(self.res["intel"]["vt_files"]["malicious"], 1)

    def test_key_never_written(self):
        for dp, dn, fn in os.walk(self.out):
            for f in fn:
                with open(os.path.join(dp, f), "rb") as fh:
                    self.assertNotIn(KEY.encode(), fh.read(), f)

    def test_cache_avoids_repeat_queries(self):
        Mock.hits.clear()
        self.analyse("--vt-key", KEY, "--vt-rate", "6000")
        self.assertEqual(Mock.hits, [], "second run should be served from the cache")

    def test_bad_key_is_graceful(self):
        out = self.analyse("--vt-key", "wrong", "--vt-rate", "6000", "--no-cache")
        self.assertIn("rejected the API key", out)

    def test_offline_mode(self):
        Mock.hits.clear()
        out = self.analyse("--offline", "--no-cache")
        self.assertEqual(Mock.hits, [])
        self.assertIn("reports in", out)

    def test_report_has_intel_tab(self):
        with open(os.path.join(self.out, "triage.html")) as fh:
            page = fh.read()
        self.assertIn('"intel_vt"', page)
        self.assertNotIn(KEY, page)

    def test_samples_extracted_read_only(self):
        for dp, dn, fn in os.walk(os.path.join(self.out, "case")):
            for f in fn:
                mode = os.stat(os.path.join(dp, f)).st_mode
                self.assertFalse(mode & 0o111, f"{f} is executable")


class SafeExtract(unittest.TestCase):
    def _tar(self, members):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, kind in members:
                ti = tarfile.TarInfo(name)
                if kind == "sym":
                    ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
                    tf.addfile(ti)
                else:
                    data = b"x"
                    ti.size, ti.mode = 1, 0o755
                    tf.addfile(ti, io.BytesIO(data))
        d = tempfile.mkdtemp()
        p = os.path.join(d, "a.tar.gz")
        with open(p, "wb") as fh:
            fh.write(buf.getvalue())
        return d, p

    def test_traversal_rejected(self):
        d, p = self._tar([("case/../../evil", "file")])
        with self.assertRaises(SystemExit):
            an.safe_extract(p, os.path.join(d, "x"))
        self.assertFalse(os.path.exists(os.path.join(d, "evil")))
        shutil.rmtree(d)

    def test_symlink_skipped_and_no_exec_bit(self):
        d, p = self._tar([("case/link", "sym"), ("case/evidence/x.sample", "file")])
        dest = os.path.join(d, "x")
        os.makedirs(dest)
        an.safe_extract(p, dest)
        self.assertFalse(os.path.lexists(os.path.join(dest, "case/link")))
        self.assertEqual(os.stat(os.path.join(dest, "case/evidence/x.sample")).st_mode & 0o777, 0o400)
        shutil.rmtree(d)

    def test_leading_dot_names_and_duplicates(self):
        d, p = self._tar([("case/.hidden/x.sample", "file"), ("case/.hidden/x.sample", "file")])
        dest = os.path.join(d, "x")
        os.makedirs(dest)
        an.safe_extract(p, dest)                       # duplicate must not crash
        self.assertTrue(os.path.isfile(os.path.join(dest, "case/.hidden/x.sample")))
        shutil.rmtree(d)

    def test_crafted_hashes_and_ips_never_reach_urls(self):
        self.assertEqual(an.norm_ip("8.8.8.8%/../x"), "8.8.8.8")   # only the clean form reaches a URL
        self.assertIsNone(an.norm_ip("8.8.8.8/../../users"))
        self.assertEqual(an.norm_ip("::ffff:8.8.8.8"), "8.8.8.8")
        self.assertFalse(an.valid_sha("../../users/me"))
        res = {"inventory": {"processes": {"cols": ["exe", "package", "sha256"],
                                           "rows": [["/x", "", "../../users/me"],
                                                    ["/y", "", "a" * 64]]}},
               "evidence": [], "findings": []}
        ips, hashes = an.gather(res, None)
        self.assertEqual(list(hashes), ["a" * 64])

    def test_public_ip(self):
        for ip, want in (("8.8.8.8", True), ("10.1.2.3", False), ("100.64.0.1", False),
                         ("203.0.113.5", False), ("::ffff:1.1.1.1", True), ("224.0.0.1", False),
                         ("fe80::1%eth0", False), ("bogus", False)):
            self.assertEqual(an.public_ip(ip), want, ip)


if __name__ == "__main__":
    unittest.main(verbosity=2)
