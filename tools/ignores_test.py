#!/usr/bin/env python3
"""Tests tools/ignores.py on fabricated input: the ignore pattern finds a test's fn past other
attributes, and the log reader tells ok, failed, missing and extra tests apart. Exit 1 on a mismatch."""
import os, sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ignores

SRC = '''#[test]
#[ignore = "sync rewrite: copies"]
fn a_spec_x_1() {}
    #[test]
    #[ignore = "sync rewrite: keys"]
    #[allow(unused)]
    pub fn b() {}
#[ignore = "by hand: slow"]
fn c() {}
'''
ok = True
got = [(m.group(1), m.group(2)) for m in ignores.IGNORE.finditer(SRC)]
if got != [("sync rewrite: copies", "a_spec_x_1"), ("sync rewrite: keys", "b"), ("by hand: slow", "c")]:
    print(f"FAIL pattern: {got}")
    ok = False
LOG = """test m::a_spec_x_1 ... ok
test n::b ... FAILED
test n::b_large ... ok
test result: FAILED. 2 passed; 1 failed
"""
got = ignores.verdicts(LOG, {"a_spec_x_1", "b", "d"})
if got != ({"a_spec_x_1": "ok", "b": "FAILED", "d": "missing"}, ["n::b_large ok"]):
    print(f"FAIL verdicts: {got}")
    ok = False
# the tree's own: every find names a crate and a fn
for crate, path, line, fn, reason in ignores.find("sync rewrite: "):
    if not (crate and fn and reason.startswith("sync rewrite: ")):
        print(f"FAIL find: {crate} {path}:{line} {fn}")
        ok = False
print(f"ignores_test: {'ok' if ok else 'FAILED'}")
sys.exit(0 if ok else 1)
