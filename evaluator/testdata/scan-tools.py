#!/usr/bin/env python3
"""Controlled scanner responses for tests of the real composite shell blocks."""

import json
import os
from pathlib import Path
import shutil
import sys

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["TEST_CALL_LOG"], "a") as log:
    log.write(json.dumps([tool, *args]) + "\n")

if tool == "sleep":
    sys.exit(0)
if tool == "curl":
    if os.environ.get("TEST_ERROR") == "installer":
        sys.exit(17)
    print("exit 0")
    sys.exit(0)
if tool == "sudo":
    sys.stdin.read()
    sys.exit(0)

error = os.environ.get("TEST_ERROR", "")
vex = os.environ.get("TEST_VEX", "available")
cache = Path(os.environ["TRIVY_CACHE_DIR"]) / "vex/repositories/fixture"
if tool == "trivy" and args[:3] == ["vex", "repo", "download"]:
    if vex != "missing":
        cache.mkdir(parents=True, exist_ok=True)
    if vex in ("available", "partial", "invalid"):
        document = {"statements": []} if vex != "invalid" else {"statements": "invalid"}
        (cache / "fixture.openvex.json").write_text(json.dumps(document))
    sys.exit(17 if vex in ("missing", "partial") else 0)

if tool == "trivy" and args[0] == "convert":
    sys.exit(9 if error == "convert" else 0)

if tool == "trivy":
    scanner = args[args.index("--scanners") + 1]
    if error == scanner:
        sys.exit(7)
    output = Path(args[args.index("--output") + 1])
    if scanner == "secret":
        secrets = [{"RuleID": "fixture-secret"}] if os.environ.get("TEST_SECRET") else []
        output.write_text(json.dumps({"Results": [{"Secrets": secrets}]}))
    elif os.environ.get("TEST_MALFORMED"):
        output.write_text('{"Results": [')
    elif os.environ.get("TEST_CLEAN") or os.environ.get("TEST_VEX_SUPPRESS"):
        output.write_text('{"Results": []}')
    else:
        shutil.copyfile(os.environ["TEST_TRIVY_REPORT"], output)
    sys.exit(0)

if tool == "grype":
    if error == "grype":
        sys.exit(8)
    output = Path(next(arg.removeprefix("json=") for arg in args if arg.startswith("json=")))
    suppressed = os.environ.get("TEST_VEX_SUPPRESS") and "--vex" in args
    if os.environ.get("TEST_CLEAN") or suppressed:
        output.write_text('{"matches": []}')
    else:
        shutil.copyfile(os.environ["TEST_GRYPE_REPORT"], output)
    sys.exit(0)

raise RuntimeError(f"Unexpected fixture command: {tool} {args}")
