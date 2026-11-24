#!/usr/bin/env python3
"""Tests tools/deprecated_probe.py on fabricated input: --dead's narrowing and its dead-list filter,
and the use search's parse of both message forms. Exit 1 on a mismatch."""
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
# lines 8 and 9 narrowed; X, Q and R leave every `pub use` (a statement left empty goes, its lines
# left blank so line numbers stay; X2 stays)
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
# an error naming the alias a dropped `pub use` gave names its item
if deprecated_probe.aliases(SRC) != {"Z": "Y", "S": "R"}:
    print(f"FAIL aliases: {deprecated_probe.aliases(SRC)!r}")
    ok = False
ERR = "core/x/src/a.rs:3:5: error[E0364]: `X` is private, and cannot be re-exported"
DEAD = "core/x/src/a.rs:9:8: warning: function `f` is never used"
if not (deprecated_probe.ERROR.match(ERR) and deprecated_probe.DEAD.match(DEAD) and not deprecated_probe.ERROR.match(DEAD)):
    print("FAIL patterns")
    ok = False
# a use in the short form (workspace clippy) and in rustc's long form (cargo-fuzz), from its cwd
SHORT = "core/x/src/b.rs:4:9: warning: use of deprecated method `osis_x::T::f`: \n"
LONG = "warning: use of deprecated function `osis_x::g`\n  --> fuzz_targets/t.rs:7:13\n   |\n"
root = deprecated_probe.ROOT
got = deprecated_probe.use_sites(SHORT, root) + deprecated_probe.use_sites(LONG, os.path.join(root, "core/test/fuzz"))
want = [("core/x/src/b.rs", 4, "osis_x::T::f"), ("core/test/fuzz/fuzz_targets/t.rs", 7, "osis_x::g")]
if got != want:
    print(f"FAIL use_sites:\n got  {got!r}\n want {want!r}")
    ok = False
# a warning naming only methods of a narrowed type used outside is left out; one naming an unused
# method (or a same-named method of another type) stays
items = {("T", "a"): ["core/x/src/a.rs:5"], ("T", "b"): ["core/x/src/a.rs:9"], ("U", "a"): ["core/x/src/a.rs:20"]}
used = {("T", "a"), ("T", "b")}
cases = [("core/x/src/a.rs:5:12: warning: methods `a` and `b` are never used", ["a", "b"]),
         ("core/x/src/a.rs:20:12: warning: method `a` is never used", []),
         ("core/x/src/a.rs:5:12: warning: methods `a` and `c` are never used", ["a"])]
for w, want in cases:
    if deprecated_probe.outside(w, items, used)[1] != want:
        print(f"FAIL outside {w!r}: want {want}")
        ok = False
print(f"deprecated probe: {'ok' if ok else 'FAILED'}")
sys.exit(0 if ok else 1)
