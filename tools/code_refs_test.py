#!/usr/bin/env python3
"""Tests tools/code_refs.py's citation forms on fabricated notes against a fabricated code: each
form passes when its name, family or file is in the code and fails when it is not, words that are no code
name are not checked, `Type::item` checks the item is the type's, Rust doc comments are checked
against Rust code with its comments left out, and a stale allow-list line fails. Exit 1 on a mismatch."""
import os, sys, tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import code_refs

WORDS = {"Engine", "tick", "held_set", "LocalPeer", "MAX_PROOFS", "admin_only_x", "admin_only_y",
         "rotation_holds_spec_crypto_4", "mod", "rs", "Kind", "Plain", "Handle", "Open", "Other", "default", "Std",
         "push"}
WORDS |= {code_refs.SPEC_TAIL.sub("", w) for w in WORDS if "_spec_" in w}
MEMBERS = {"Engine": {"tick"}, "Kind": {"Plain"}, "Open": {"$"}, "Handle": {"Deref=Engine"}, "Std": {"len"}}
ENDS = {"core/engine/src/apply/mod.rs", "engine/src/apply/mod.rs", "src/apply/mod.rs", "apply/mod.rs", "mod.rs"}

# (text, stale?)
CASES = [
    ("`Engine::tick`", False),
    ("`Engine::gone`", True),                     # a path segment
    ("`gone()`", True),                           # a call
    ("`held_set`", False),
    ("`held_sets`", True),                        # a word, not a substring
    ("`LocalPeer`", False),
    ("`LocalPier`", True),                        # CamelCase with an inner capital
    ("`MAX_PROOFS`", False),
    ("`MAX_PROOF`", True),
    ("`rotation_holds`", False),                  # a test less its spec tail
    ("`admin_only_{x,y}`", False),
    ("`admin_only_{x,z}`", True),
    ("`apply/mod.rs`", False),
    ("`core/engine/src/apply/mod.rs`", False),
    ("`core/engine/src/apply/gone.rs`", True),
    ("`Engine`", False),
    ("`Gone`", True),                             # a span of one capitalised word
    ("`Gone away`", False),                       # a plain word
    ("`gone`", False),
    ("`held_*`", False),                          # a family: some word starts with it
    ("`admin_only_*`", False),
    ("`foo_*`", True),                            # a family whose tests are all gone
    ("`held_sets_*`", True),
    ("`held_*_bar_*`", False),                    # a pattern: its lead is checked, not `_bar_`
    ("`foo_*_bar_*`", True),
    ("`foo*`", False),
    ("`<my_name>`", False),                       # a placeholder
    ("`--no_such`", False),                       # a flag
    ("`_large`", False),                          # a suffix
    ("```\ngone_fn()\n```", False),               # a fenced sketch
    ("`allowed_name`", False),                    # listed
    ("`Engine::held_set`", True),                 # a word, but not the type's
    ("`Kind::Plain`", False),
    ("`Kind::LocalPeer`", True),
    ("`Handle::tick`", False),                    # through `Deref`
    ("`Open::held_set`", False),                  # a type a macro fills in
    ("`Engine::default`", False),                 # a derived trait's
    ("`Other::held_set`", False),                 # not our type: the word is checked
    ("`Kind::Plain::held_set`", False),           # a variant's payload's item
    ("`Std::push`", True),
    ("`Std::push` x", False),                     # as the code writes it (WORDS has `Std::push` below)
]

bad = 0
for text, want in CASES:
    words = WORDS | {"Std::push"} if text.endswith(" x") else WORDS
    got = [e for e in code_refs.stale({"notes/n.md": text}, words, ENDS, {"allowed_name": (1, "placeholder")}, MEMBERS) if "notes/n.md" in e]
    if bool(got) != want:
        bad += 1
        print(f"FAIL {text!r}: expected {'stale' if want else 'fine'}, got {got}")

# the allow list: a listed name in the code, cited nowhere, or without a reason
ALLOW = {"tick": (1, "third-party"), "never_cited": (2, "placeholder"), "no_reason": (3, "")}
got = "\n".join(code_refs.stale({"notes/n.md": "`no_reason`"}, WORDS, ENDS, ALLOW))
for want in ("`tick` is in the code", "`never_cited` is cited nowhere", "`no_reason` has no reason"):
    if want not in got:
        bad += 1
        print(f"FAIL allow list: {want!r} not reported:\n{got}")

# Rust sources: members by brace depth, doc comments checked, a name only a comment keeps is none
SRC = """//! Module doc: `Peer::wake` and `only_in_comment` and `gone_fn()`.
use std::ops::Deref;
/// A struct (`Peer::name`).
pub struct Peer {
    pub name: String,
    #[allow(dead_code)]
    count: u32, // `comment_word` is no code
}
pub enum Kind { Plain, Other(u8) }
enum Big {
    First,
    Second { inner: u8 },
}
impl<T: Clone> Trait for Peer where T: Copy {
    fn wake(&self) -> u32 {
        let s = Peer { name: "lit_word".into(), count: 0 };
        fn nested() {}
        0
    }
    const LIMIT: u32 = 3;
}
struct Wrap(Peer);
impl Deref for Wrap {
    type Target = Peer;
    fn deref(&self) -> &Peer { &self.0 }
}
macro_rules! m { ($($f:ident),*) => { struct Made { $($f: u8,)* } } }
/* only_in_block */
"""
DOCS = [("`Peer::wake`", False), ("`Peer::count`", False), ("`Peer::nested`", True), ("`Peer::LIMIT`", False),
        ("`Kind::Other`", False), ("`Big::Second`", False), ("`Big::inner`", True), ("`Wrap::wake`", False),
        ("`Made::name`", False), ("`lit_word`", False), ("`comment_word`", True), ("`only_in_block`", True),
        ("`only_in_comment`", True), ("`Peer::gone`", True)]
with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "src"))
    open(os.path.join(d, "src/lib.rs"), "w").write(SRC)
    words, ends, members, rdocs = code_refs.code_names(d, ["src/lib.rs"])
    doc = rdocs.get("src/lib.rs", "")
    for want in ("`only_in_comment`", "`Peer::name`"):
        if want not in doc:
            bad += 1
            print(f"FAIL doc comments: {want} not read:\n{doc}")
    got = "\n".join(code_refs.stale({"src/lib.rs": doc}, words, ends, {}, members))
    for want in ("`only_in_comment`", "`gone_fn`"):
        if want not in got:
            bad += 1
            print(f"FAIL doc comment: {want} not reported:\n{got}")
    if "`Peer::wake`" in got or "`Peer::name`" in got:
        bad += 1
        print(f"FAIL doc comment: a defined member reported:\n{got}")
    for text, want in DOCS:
        g = [e for e in code_refs.stale({"notes/n.md": text}, words, ends, {}, members)]
        if bool(g) != want:
            bad += 1
            print(f"FAIL rust {text!r}: expected {'stale' if want else 'fine'}, got {g}")
n = len(CASES) + 3 + 4 + len(DOCS)
print(f"code_refs_test: {n - bad}/{n} passed")
sys.exit(1 if bad else 0)
