#!/usr/bin/env python3
"""Tests tools/spec_map.py's anchor check (stray_anchors) on planted citations: an anchor naming
text of its section passes, one naming nothing there is reported (fail closed), and a file outside
ANCHOR_CHECKED is not checked. Usage: tools/spec_map_test.py (exit 1 on a failure)."""
import os, sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import spec_map

SENTS = [
    ("spec/sync-ids.md", "6", "- **Relay-only** entry: the blob is not stored."),
    ("spec/sync-ids.md", "6.1", "**Taken once**: a repeat is dropped."),
    ("spec/sync-ids.md", "5", "Tombstones of deleted entries."),
    ("spec/wire.md", "11.1", "`id` is 0 in a push."),
    ("spec/crypto.md", "4", "Anything."),
]
RULES = {("spec/sync-ids.md", "5", "a rules anchor")}
CASES = [  # (citation, reported)
    (("spec/sync-ids.md", "6", "relay-only"), False),
    (("spec/sync-ids.md", "6", "Relay-Only"), False),  # case and markup ignored
    (("spec/sync-ids.md", "6", "taken once"), False),  # a subsection's text counts for §6
    (("spec/sync-ids.md", "6", "relay-only: the gloss after a colon is free"), False),
    (("spec/sync-ids.md", "6", "relay-only; taken once"), False),
    (("spec/sync-ids.md", "6", "relay-only; floor"), True),  # every name must match
    (("spec/sync-ids.md", "6.1", "relay-only"), True),  # §6.1 does not see §6's text
    (("spec/sync-ids.md", "5", "relay-only"), True),  # another section's rule
    (("spec/sync-ids.md", "5", "a rules anchor"), False),
    (("spec/sync-ids.md", "7", "anything"), True),  # a section with no text
    (("spec/wire.md", "11.1", "`id` is 0 in a push"), False),
    (("spec/wire.md", "11.1", "ids"), True),
    (("spec/crypto.md", "4", "free text"), False),  # not in ANCHOR_CHECKED
    (("spec/sync-ids.md", "6", None), False),  # no anchor
]
fails = 0
for cite, want in CASES:
    got = spec_map.stray_anchors([{"id": "t", "cites": [cite]}], SENTS, RULES)
    if bool(got) != want:
        print(f"FAIL {cite}: {'reported' if got else 'passed'}")
        fails = 1
# The repo's own citations are clean (what --gaps checks).
tests = spec_map.rust_tests() + spec_map.vector_cases()
rk = {(f, s, a) for f, s, a, _ in spec_map.RULES}
for p in spec_map.stray_anchors(tests, spec_map.spec_sentences(), rk):
    print(f"FAIL {p}")
    fails = 1
sys.exit(fails)
