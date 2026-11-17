# keel-leaks15
- No row-level dump of an engine's local rows for tests: finding which row a census family gained (S1's grantee) took a temporary `scan_local` hook and a hand-written diff script each time. A test-only `Engine::local_rows` beside `local_census` would make storage leaks a one-step read.
- No way to ask why a thing is kept: a temporary need-path walk over `needers`/`rooted` (printing which rooted clause held) found leaks 15 and 19 at once; worth keeping as a test helper.
- Running two growth tests at once interleaves their stderr dumps; run one per dump.
