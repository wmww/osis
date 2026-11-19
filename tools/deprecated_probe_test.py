#!/usr/bin/env python3
"""Tests tools/deprecated_probe.py's --dead narrowing on a fabricated source. Exit 1 on a mismatch."""
import os, sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import deprecated_probe

SRC = """pub use a::{X, Y as Z, W};
pub use b::Q;
pub use c::R as S;
pub use d::{
    X,
};
pub use e::X2;
pub struct X;
pub fn f() {}
pub fn g() {}
"""
# lines 8 and 9 narrowed; X, Q and R leave every `pub use` (a statement left empty goes; X2 stays)
WANT = """pub use a::{Y as Z, W};



pub use e::X2;
pub(crate) struct X;
pub(crate) fn f() {}
pub fn g() {}
"""
got = deprecated_probe.narrowed(SRC, [8, 9], {"X", "Q", "R"})
ok = got == WANT
if not ok:
    print(f"FAIL narrowed:\n got  {got!r}\n want {WANT!r}")
ERR = "core/x/src/a.rs:3:5: error[E0364]: `X` is private, and cannot be re-exported"
DEAD = "core/x/src/a.rs:9:8: warning: function `f` is never used"
if not (deprecated_probe.ERROR.match(ERR) and deprecated_probe.DEAD.match(DEAD) and not deprecated_probe.ERROR.match(DEAD)):
    print("FAIL patterns")
    ok = False
print(f"deprecated probe: {'ok' if ok else 'FAILED'}")
sys.exit(0 if ok else 1)
