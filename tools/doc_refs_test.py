#!/usr/bin/env python3
"""Tests tools/doc_refs.py's pointer forms on fabricated docs: each form passes when its section
exists and fails when it does not, and words that are no section name are not checked. Exit 1 on a mismatch."""
import os, sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import doc_refs

SPEC = """# Sync
## 1. Blobs
- **Framing**: bytes.
## 2. Labels
### 2.1 Heads
**Claim set**: a set.
  After syncing: indented lead.
```
Error  [0, id, code]
```
Each side sends `Hello := [x]`.
## 3. Pushes
### Own bodies
"""
NOTE = """# Notes
## Rules
- **One call**: one API call.
## Handle and lifecycle
"""
DOCS = {"spec/s.md": SPEC, "notes/n.md": NOTE, "issues/i.md": "# I\n"}

# (text, stale?)
CASES = [
    ("see spec/s.md §2", False),
    ("see spec/s.md §2.1", False),
    ("see spec/s.md §4", True),
    ("see spec/s.md §2.2", True),
    ("spec/s.md §1, §3 and §2.1", False),
    ("spec/s.md §1, §9", True),
    ("spec/s.md §1-§3", False),
    ("spec/s.md §1-4", True),
    ("spec/s.md §2 Claim set: x", False),
    ("spec/s.md §2 (Claim set)", False),
    ("spec/s.md §2 Claim)", False),               # the start of a lead
    ("spec/s.md §1 Claim set", True),             # a lead of another section
    ("spec/s.md §1, §2 Claim set", False),        # several sections: the file's leads
    ("spec/s.md §3 Own bodies)", False),          # a subheading inside §3
    ("spec/s.md §2 After syncing", False),        # an indented `Lead:`
    ("spec/s.md §2 (Error 4)", False),            # a fenced grammar's name
    ("spec/s.md §2 (Hello: one frame)", False),   # `Name :=`
    ("spec/s.md §2 (Shredding)", True),
    ("spec/s.md §2 (MAX_PROOFS)", False),         # a constant
    ("spec/s.md §2 (TLA S4)", False),             # an acronym
    ("spec/s.md §2 (the anchor)", False),         # lowercase: an anchor, not a section
    ("spec/s.md §2. The next sentence", False),
    ("notes/n.md One call", False),
    ("notes/n.md Handle and lifecycle: x", False),
    ("notes/n.md Handle and sync: x", True),
    ("notes/n.md, Rules", False),
    ("notes/n.md (Futures)", True),
    ("notes/n.md `Osis::open`", False),
    ("notes/n.md Osis::open", False),
    ("notes/n.md\nNext line", False),             # a new line is no section name
    ("issues/i.md Anything", False),              # issues: the file only
    ("issues/gone.md", True),
    ("notes/gone.md", True),
]

bad = 0
for text, stale in CASES:
    got = list(doc_refs.refs("x.rs", text, DOCS.get))
    if bool(got) != stale:
        bad += 1
        print(f"FAIL {text!r}: expected {'stale' if stale else 'fine'}, got {got}")
print(f"doc_refs_test: {len(CASES) - bad}/{len(CASES)} passed")
sys.exit(1 if bad else 0)
