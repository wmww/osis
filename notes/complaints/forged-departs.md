# forged-departs
> Summary: Workflow notes from the departs-mark fix.

- `withheld_departures` (rotation::tests) checks only that departed peers open no epoch *made by a rotator that saw them depart*; it cannot see a forged entry making an old epoch cover a departure. The end-state check that matters ("the owner, after ensure_rotated, encrypts under no epoch a peer below its role holds") lives in `tests_departs::forged_departs`; it found a separate attribution hole (issues/departure-attributed-to-later-audit-drop.md).
