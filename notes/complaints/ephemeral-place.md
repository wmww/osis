# ephemeral-place
- Reading the brief's notes with `cat` (ephemeral.md + the issue, 35 KB) spilled to a persisted-output file, and `cat` of that file spilled again; the Read tool on the note directly was the way. Big notes: Read with offsets, not cat.
- The step-1 interim "placing persists" rule was load-bearing for internal code (`contact_card`'s `make_group` relied on it) and for the CLI tests' `create --in home`; grep `make_group`/`place` callers in src when changing persistence rules.
