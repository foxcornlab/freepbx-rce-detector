#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# freepbx_detector.py -- triage scanner for CVE-2025-57819
# (FreePBX Endpoint Manager unauthenticated SQL injection -> RCE)
#
# Copyright (c) 2026 Vineeth Kumar, Foxcorn Lab
# SPDX-License-Identifier: MIT
#
# What this does:
#   scan     - fingerprint a host for FreePBX, pull whatever version info is
#              exposed, and give a patch verdict against the fixed Endpoint
#              Manager releases. Sends only benign GET requests, no payloads.
#   logcheck - hunt web access logs for exploitation attempts (ajax.php +
#              brand= with SQLi markers).
#
# What this does NOT do: it never sends injection payloads. Version-based
# triage only. If the Endpoint Manager version can't be read remotely, the
# verdict says so instead of guessing.

import argparse
import json
import re
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

VERSION = "1.0.0"

# Fixed Endpoint Manager releases per the Sangoma security advisory
# (GHSA-m42g-xg4c-5f3h) and the CVE-2025-57819 description:
#   15.x -> 15.0.66, 16.x -> 16.0.89, 17.x -> 17.0.3
# Note: at least one third-party write-up cites 16.0.92; the official
# advisory and the CVE record say 16.0.89, which is what we enforce.
PATCHED = {
    "15": (15, 0, 66),
    "16": (16, 0, 89),
    "17": (17, 0, 3),
}

# Markers that say "this is a FreePBX admin panel"
FREEPBX_MARKERS = [
    re.compile(r"<title>[^<]*FreePBX", re.I),
    re.compile(r"freepbx", re.I),
    re.compile(r"FreePBX Administration", re.I),
]

# Version strings occasionally exposed on the login page / assets
VERSION_RES = [
    re.compile(r"FreePBX\s+(\d+)\.(\d+)\.(\d+)", re.I),
    re.compile(r"version\s*[:=]\s*['\"]?(\d+)\.(\d+)\.(\d+)", re.I),
]

# Endpoint Manager module version, when exposed (rare pre-auth)
ENDPOINT_RES = [
    re.compile(r"endpoint[^0-9]*(\d+)\.(\d+)\.(\d+)", re.I),
]

# Log-hunt indicators for CVE-2025-57819 exploitation attempts
LOG_INDICATORS = [
    re.compile(r"ajax\.php", re.I),
    re.compile(r"brand\s*=", re.I),
]
SQLI_MARKERS = [
    re.compile(r"extractvalue", re.I),
    re.compile(r"updatexml", re.I),
    re.compile(r"union(\s|%20|\+)+.*select", re.I),
    re.compile(r"insert(\s|%20|\+)+into", re.I),
    re.compile(r"concat\s*\(", re.I),
    re.compile(r"0x[0-9a-f]{2,}", re.I),
    re.compile(r"--(\s|$)", re.I),
    re.compile(r"sleep\s*\(", re.I),
    re.compile(r"benchmark\s*\(", re.I),
]


def _ctx(insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(url, timeout, insecure, headers=None):
    req = urllib.request.Request(
        url,
        headers=headers or {"User-Agent": "freepbx-detector/%s" % VERSION},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                     context=_ctx(insecure)) as r:
            body = r.read(600000).decode("utf-8", "replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(600000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body
    except Exception as e:
        return None, {}, "ERROR: %s" % e


def ver_tuple(m):
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def verdict_for(major, ver):
    patched = PATCHED.get(major)
    if not patched:
        return "unknown", "major version %s not in 15/16/17 matrix" % major
    if ver < patched:
        return ("vulnerable",
                "below fixed release %s" % ".".join(map(str, patched)))
    return "patched", "at or above fixed release %s" % ".".join(map(str, patched))


def scan_target(target, timeout=10, insecure=False):
    base = target if "://" in target else "http://%s" % target
    result = {
        "target": target,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "is_freepbx": False,
        "freepbx_version": None,
        "endpoint_version": None,
        "verdict": "not-freepbx",
        "detail": "no FreePBX markers found",
    }

    status, _, body = fetch(base.rstrip("/") + "/admin/config.php",
                            timeout, insecure)
    if status is None:
        result["verdict"] = "unreachable"
        result["detail"] = body
        return result
    if status in (301, 302, 303, 307, 308):
        result["detail"] = "redirected (HTTP %s), check the admin URL" % status

    if not any(rx.search(body) for rx in FREEPBX_MARKERS):
        return result
    result["is_freepbx"] = True

    for rx in VERSION_RES:
        m = rx.search(body)
        if m:
            result["freepbx_version"] = "%d.%d.%d" % ver_tuple(m)
            break
    for rx in ENDPOINT_RES:
        m = rx.search(body)
        if m:
            result["endpoint_version"] = "%d.%d.%d" % ver_tuple(m)
            break

    if result["endpoint_version"]:
        major = result["endpoint_version"].split(".")[0]
        v, d = verdict_for(major, ver_tuple(re.match(
            r"(\d+)\.(\d+)\.(\d+)", result["endpoint_version"])))
        result["verdict"] = v
        result["detail"] = "endpoint manager %s: %s" % (
            result["endpoint_version"], d)
    else:
        result["verdict"] = "needs-manual-check"
        result["detail"] = (
            "FreePBX detected but Endpoint Manager version is not exposed "
            "pre-auth. Verify in Module Admin: needs >= 15.0.66 / 16.0.89 / "
            "17.0.3 (CVE-2025-57819).")
    return result


def logcheck(path):
    hits = []
    with open(path, "r", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            if not all(rx.search(line) for rx in LOG_INDICATORS):
                continue
            markers = sorted({rx.pattern for rx in SQLI_MARKERS
                              if rx.search(line)})
            if markers:
                ip = line.split()[0] if line.split() else "?"
                hits.append({"line": lineno, "ip": ip,
                             "markers": markers,
                             "raw": line.strip()[:300]})
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Triage scanner for CVE-2025-57819 "
                    "(FreePBX Endpoint Manager unauth SQLi -> RCE). "
                    "Detection only, no payloads are sent.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="fingerprint host(s) for FreePBX")
    s.add_argument("targets", nargs="+",
                   help="host(s), e.g. pbx.example.com or http://10.0.0.5")
    s.add_argument("--timeout", type=int, default=10)
    s.add_argument("-k", "--insecure", action="store_true",
                   help="skip TLS verification")
    s.add_argument("--json", action="store_true", help="JSON output")

    l = sub.add_parser("logcheck",
                       help="hunt access logs for exploitation attempts")
    l.add_argument("logfile", help="path to access log")
    l.add_argument("--json", action="store_true", help="JSON output")

    args = ap.parse_args(argv)

    if args.cmd == "scan":
        results = [scan_target(t, args.timeout, args.insecure)
                   for t in args.targets]
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                print("[%s] %s" % (r["verdict"].upper(), r["target"]))
                print("  freepbx: %s  endpoint: %s" % (
                    r["freepbx_version"] or "n/a",
                    r["endpoint_version"] or "n/a"))
                print("  %s" % r["detail"])
        # exit 2 if anything looks vulnerable
        if any(r["verdict"] == "vulnerable" for r in results):
            return 2
        return 0

    hits = logcheck(args.logfile)
    if args.json:
        print(json.dumps(hits, indent=2))
    else:
        if not hits:
            print("No CVE-2025-57819 exploitation indicators found.")
        for h in hits:
            print("line %d | ip %s | markers: %s" % (
                h["line"], h["ip"], ", ".join(h["markers"])))
            print("  %s" % h["raw"])
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
