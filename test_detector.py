#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# test_detector.py -- self-tests for freepbx_detector.py
#
# Copyright (c) 2026 Vineeth Kumar, Foxcorn Lab
# SPDX-License-Identifier: MIT
#
# Everything runs against a local mock FreePBX admin page, nothing leaves
# the box:
#
#     python3 test_detector.py
#
# Exit code 0 = all green.

import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import freepbx_detector as d


def mock_freepbx_page(endpoint_version=None, freepbx_version="16.0.40.7"):
    ver = ""
    if freepbx_version:
        ver = "<title>FreePBX %s Administration</title>" % freepbx_version
    ep = ""
    if endpoint_version:
        ep = "<!-- endpoint manager %s -->" % endpoint_version
    return (
        "<html><head>%s</head>"
        "<body>FreePBX Administration %s</body></html>" % (ver, ep)
    )


class _Handler(BaseHTTPRequestHandler):
    # set per-test by the harness
    page = ""

    def do_GET(self):
        body = type(self).page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def scan(self, page):
        _Handler.page = page
        return d.scan_target("http://127.0.0.1:%d" % self.port)

    def test_vulnerable_endpoint(self):
        r = self.scan(mock_freepbx_page(endpoint_version="16.0.55"))
        self.assertTrue(r["is_freepbx"])
        self.assertEqual(r["verdict"], "vulnerable")
        self.assertIn("16.0.89", r["detail"])

    def test_patched_endpoint(self):
        r = self.scan(mock_freepbx_page(endpoint_version="16.0.89"))
        self.assertEqual(r["verdict"], "patched")

    def test_patched_above_fixed(self):
        r = self.scan(mock_freepbx_page(endpoint_version="17.0.10"))
        self.assertEqual(r["verdict"], "patched")

    def test_endpoint_version_hidden(self):
        # most common real-world case: honest triage, not a miss
        r = self.scan(mock_freepbx_page())
        self.assertTrue(r["is_freepbx"])
        self.assertEqual(r["verdict"], "needs-manual-check")
        self.assertIn("Module Admin", r["detail"])

    def test_not_freepbx(self):
        _Handler.page = "<html><body>hello world</body></html>"
        r = self.scan(_Handler.page)
        self.assertFalse(r["is_freepbx"])
        self.assertEqual(r["verdict"], "not-freepbx")

    def test_unreachable(self):
        r = d.scan_target("http://127.0.0.1:1", timeout=2)
        self.assertEqual(r["verdict"], "unreachable")


class VerdictTests(unittest.TestCase):
    def test_below_fixed_is_vulnerable(self):
        v, _ = d.verdict_for("15", (15, 0, 65))
        self.assertEqual(v, "vulnerable")

    def test_at_fixed_is_patched(self):
        v, _ = d.verdict_for("16", (16, 0, 89))
        self.assertEqual(v, "patched")

    def test_unknown_major(self):
        v, detail = d.verdict_for("18", (18, 0, 1))
        self.assertEqual(v, "unknown")
        self.assertIn("18", detail)


class LogcheckTests(unittest.TestCase):
    def _write(self, lines):
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines))
        self.addCleanup(os.unlink, path)
        return path

    def test_exploit_attempt_flagged(self):
        log = self._write([
            '203.0.113.7 - - [01/Oct/2026] "GET /admin/ajax.php?module=endpointman&brand=1%27%20AND%20EXTRACTVALUE(1,CONCAT(0x5c,version())) HTTP/1.1" 200 512',
            '203.0.113.8 - - [01/Oct/2026] "GET /index.php HTTP/1.1" 200 1234',
        ])
        hits = d.logcheck(log)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["ip"], "203.0.113.7")
        self.assertTrue(any("extractvalue" in m for m in hits[0]["markers"]))

    def test_clean_log_no_hits(self):
        log = self._write([
            '203.0.113.8 - - [01/Oct/2026] "GET /admin/config.php HTTP/1.1" 200 1234',
        ])
        self.assertEqual(d.logcheck(log), [])

    def test_ajax_without_brand_ignored(self):
        log = self._write([
            '203.0.113.9 - - [01/Oct/2026] "GET /admin/ajax.php?module=core HTTP/1.1" 200 100',
        ])
        self.assertEqual(d.logcheck(log), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
