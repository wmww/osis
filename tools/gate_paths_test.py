#!/usr/bin/env python3
"""Tests tools/gate_paths.py's comments-only judgment: whole-line comments on fabricated sources, and
two real commits (sync-spec's pointer sweep, whose 14 string lines fail it, and a comments-only one).
The path selection itself: tools/gate_select_test.sh. Exit 1 on a mismatch."""
import os, sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate_paths as g

fail = n = 0


def check(name, got, want):
    global fail, n
    n += 1
    if got != want:
        print(f"FAIL {name}: got {got!r}, want {want!r}")
        fail = 1


SRC = r'''fn a<'l>(x: &'l str) {
    // plain
    let s = "x
// in a string
";
    let r = r#"
// in a raw string "
"#;
    /* block /* nested */
// in a block
    */
    let c = '"'; // trailing
    // after a char literal holding a quote
    let e = '\'';
    // after an escaped quote
    let b = br##"
// in a byte raw string
"##;
    m! {
        /// doc in a macro call
        // plain in a macro call
    }
}
/// doc
//! inner doc
//// plain, four slashes
/** block doc */
macro_rules! f {
    () => {
        /// doc in a macro definition
    };
}
'''
lines = g.comment_lines(SRC)
check("whole-line comments", sorted(lines), [2, 13, 15, 20, 21, 24, 25, 26, 30])
check("doc kinds", [n for n in sorted(lines) if g.is_doc(lines[n])], [20, 24, 25, 30])
macro = g.macro_lines(SRC)
check("doc comments inside macros", [n for n in (20, 24, 25, 30) if n in macro], [20, 30])
for text, want in [("x = foo!", True), ("foo! ", True), ("macro_rules! f ", True), ("#!", False), ("a !=", False),
                   ("x = !", False), ("fn f", False), ("if !", True)]:
    check(f"macro_before {text!r}", g.macro_before(text), want)

# sync-spec's pointer sweep: 14 changed lines are strings (an error message, vector headers); a doc
# comment inside a macro call falls through too
bad, _ = g.rs_verdict("d8b89848d^", "d8b89848d", [p for p in g.changed("d8b89848d^", "d8b89848d") if p.endswith(".rs")])
strings = [b for b in bad if "doc comment inside a macro" not in b]
check("d8b89848d string lines", len(strings), 14)
check("d8b89848d strings named", all('"' in b for b in strings), True)
check("d8b89848d docs in a macro", len(bad) - len(strings), 2)
check("d8b89848d", g.classify("d8b89848d^", "d8b89848d")["core"], "1")
check("6050ae05f", g.classify("6050ae05f^", "6050ae05f"), dict(core="comments", gui="", unify="", doc=""))

# doc comments: a crate's doctests, unless a proc macro may read them or no crate owns the file
check("doc crates", g.doc_crates(["core/base/src/ids.rs", "core/node/tests/it/judgment.rs"]), (["osis-base", "osis-node"], []))
crates, why = g.doc_crates(["cli/src/args.rs", "core/test/fuzz/x.rs"])
check("doc in a clap crate, doc outside the workspace", (crates, [w.split(":")[0] for w in why]), ([], ["cli/src/args.rs", "core/test/fuzz/x.rs"]))

print(f"gate paths: {n} cases, {'FAILED' if fail else 'ok'}")
sys.exit(fail)
