#!/usr/bin/env python3
"""Tests tools/mutate.py's test environment: the binaries it runs outside cargo get
`.cargo/config.toml`'s `[env]` (the suite's proptest case count, no regression files), an explicit
value winning. Exit 1 on a mismatch."""
import os, sys, tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mutate

ok = True


def check(what, got, want):
    global ok
    if got != want:
        print(f"FAIL {what}: got {got!r}, want {want!r}")
        ok = False


with tempfile.TemporaryDirectory(prefix="mutate-test-") as d:
    cfg = os.path.join(d, "config.toml")
    with open(cfg, "w") as f:
        f.write('[env]\nA = "1"\nB = { value = "2", force = false }\n[target.x]\nrustflags = []\n')
    check("table and plain values", mutate.cargo_env({}, cfg), {"A": "1", "B": "2"})
    check("explicit value wins", mutate.cargo_env({"A": "9", "C": "3"}, cfg), {"A": "9", "B": "2", "C": "3"})
    # the repository's own config: what a default test run gets
    e = mutate.cargo_env({})
    check("suite case count", e.get("PROPTEST_CASES"), "32")
    check("no regression files", e.get("PROPTEST_DISABLE_FAILURE_PERSISTENCE"), "1")
    # a run sees it: a stand-in test binary printing its environment
    exe = os.path.join(d, "bin")
    with open(exe, "w") as f:
        f.write("#!/bin/sh\necho cases=$PROPTEST_CASES persist=$PROPTEST_DISABLE_FAILURE_PERSISTENCE mutant=$OSIS_MUTANT\n")
    os.chmod(exe, 0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("PROPTEST_") and k not in ("MUTATE_HEAVY", mutate.VAR)}
    [[(_, rc, out)]] = mutate.run_bins([(exe, d)], [], env, ["0"])
    check("run env", (rc, out.strip()), (0, "cases=32 persist=1 mutant=0"))
print(f"mutate: {'ok' if ok else 'FAILED'}")
sys.exit(0 if ok else 1)
