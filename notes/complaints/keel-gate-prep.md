# keel-gate-prep
- The brief counted 48 stray anchors in four sections; they spanned twenty, and `--uncited` also failed (5 tests). Run the check before writing its summary.
- A spec_map anchor wrapped across comment lines gets a double space and reads stray; keep an anchor on one line.
- doc_refs also reads `§N (anchor)`: an anchor must be a bold lead, list item or `Lead:` there, or name one before a `:`. spec_map and doc_refs check the same parentheses with different rules.
