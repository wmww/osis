# keel-workflow2
- policy.py's slow checks hid behind a per-line regex loop (old_words: 2 of 5 s); a literal-hint prefilter fixed it. A pattern with a leading `\b` or a leading alternation scans slowly in sre; write `\b` as a lookbehind after the literal.
- Moving a note section breaks pointers in code comments too (13 .rs/.toml lines here): a section move is never notes-only.
- A scripted pointer rewrite turned `file (Section)` into `file ()` where the section went away; grep `()` after such sweeps.
