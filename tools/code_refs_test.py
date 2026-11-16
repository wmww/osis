#!/usr/bin/env python3
"""Tests tools/code_refs.py's citation forms on fabricated notes against a fabricated code: each
form passes when its name or file is in the code and fails when it is not, words that are no code
name are not checked, and a stale allow-list line fails. Exit 1 on a mismatch."""
import os, sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import code_refs

WORDS = {"Engine", "tick", "held_set", "LocalPeer", "MAX_PROOFS", "admin_only_x", "admin_only_y",
         "rotation_holds_spec_crypto_4", "mod", "rs"}
WORDS |= {code_refs.SPEC_TAIL.sub("", w) for w in WORDS if "_spec_" in w}
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
    ("`Gone`", False),                            # a plain word
    ("`gone`", False),
    ("`foo_*`", False),                           # a pattern
    ("`<my_name>`", False),                       # a placeholder
    ("`--no_such`", False),                       # a flag
    ("`_large`", False),                          # a suffix
    ("```\ngone_fn()\n```", False),               # a fenced sketch
    ("`allowed_name`", False),                    # listed
]

bad = 0
for text, want in CASES:
    got = [e for e in code_refs.stale({"notes/n.md": text}, WORDS, ENDS, {"allowed_name": (1, "placeholder")}) if "notes/n.md" in e]
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
print(f"code_refs_test: {len(CASES) + 3 - bad}/{len(CASES) + 3} passed")
sys.exit(1 if bad else 0)
