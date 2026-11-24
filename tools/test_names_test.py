#!/usr/bin/env python3
"""Tests tools/test_names.py against a fake test binary's `--list`. Exit 1 on a mismatch."""
import os, subprocess, sys, tempfile

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_names.py")
ALL = ["paths::content::a_plain", "paths::content_x::b_plain", "content::c_plain", "paths::d_large",
       "tests_seq::e", "tests_seq_ops::f"]
IGNORED = ALL[:4]
fail = 0
with tempfile.TemporaryDirectory() as d:
    b = os.path.join(d, "it-0")
    with open(b, "w") as f:
        f.write("#!/bin/sh\nif [ \"$3 $4\" = \"terse --ignored\" ]; then set -- " + " ".join(IGNORED)
                + "; else set -- " + " ".join(ALL) + "; fi\nfor n; do echo \"$n: test\"; done\necho \"x: benchmark\"\n")
    os.chmod(b, 0o755)
    for args, want, rc in [
        (["--ignored", b, "paths::", "_plain"], ["paths::content::a_plain", "paths::content_x::b_plain"], 0),
        ([b, "content::"], ["paths::content::a_plain", "content::c_plain"], 0),
        ([b, "^content::"], ["content::c_plain"], 0),
        ([b, "tests_seq::"], ["tests_seq::e"], 0),
        (["--ignored", b, "tests_seq"], [], 1),
    ]:
        r = subprocess.run([sys.executable, TOOL, *args], capture_output=True, text=True)
        got = (r.stdout.split(), r.returncode)
        if got != (want, rc):
            print(f"FAIL {args[1:]}: got {got}, want {(want, rc)}")
            fail = 1
sys.exit(fail)
