# forged-departs
> Summary: Workflow notes from the departs-mark fix.

- `withheld_departures` (rotation::tests) checks only that departed peers open no epoch *made by a rotator that saw them depart*; it cannot see a forged entry making an old epoch cover a departure. The end-state check that matters ("the owner, after ensure_rotated, encrypts under no epoch a peer below its role holds") lives in `tests_departs::forged_departs`; it found a separate attribution hole (issues/departure-attributed-to-later-audit-drop.md).
- Review (fathom-forged-departs-review): the per-branch rotation filter `rotation::tests::` missed `rotation::tests_departs::` (fixed in notes/testing.md); a new test module beside `tests.rs` silently leaves the per-branch oracle set.
- Review: the brief's fix closed only departs marks; a plain `list` name of the leaver's own self-removal in a backdated entry does the same (issues/own-departure-named-by-own-entry.md). A fix for "an entry may name X" should be checked against every kind of name, not the one the report mentioned.
- Review gate: 730 s at load 27 after a rebase (main had moved under the branch), mostly re-checking deps (app/kit crates).
