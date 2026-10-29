# ephemeral-place
- Reading the brief's notes with `cat` (ephemeral.md + the issue, 35 KB) spilled to a persisted-output file, and `cat` of that file spilled again; the Read tool on the note directly was the way. Big notes: Read with offsets, not cat.
- The step-1 interim "placing persists" rule was load-bearing for internal code (`contact_card`'s `make_group` relied on it) and for the CLI tests' `create --in home`; grep `make_group`/`place` callers in src when changing persistence rules.
- Review: a counting `#[global_allocator]` in a test binary is impossible (workspace `forbid(unsafe_code)`); measured heap via `/proc/self/statm` RSS growth per write instead (40k writes, one process per config: fine, but a map-replace probe ran for minutes since each replace walks the tombstones).
