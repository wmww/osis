# The slots-join floor fails when six seeds in a row never reach slots
> Summary: osis-crdt `tests_seq::slots_join_follows_cache_plain_spec_7` fails its coverage floor (3 slots joins over 6 seeds) at some offsets on main: about 10 joins a seed on average, but a seed reaches none when its text never becomes `Slots`, and six such seeds in a row (from OSIS_CRDT_START=828121608434) give 0.
> Priority: normal
> Tags: crdt, tests

## What
The test writes a text, then a string register (upgrading the text to `Slots`), then 40 random text ops; it counts joins at the `Slots` position. Over 60 seeds from three starts it reaches 512-676 joins (floor 30), but many seeds reach none, so the gate's 6 seeds now and then reach 0 (floor 3): `joins on slots: 0 over 6 seeds, under the floor 3 (1 per 2 seeds)`. Seen at a gate on a branch not touching the generator; the same offset fails on main's binary.

## Fix
Make every seed reach slots by construction (the random ops must not undo the upgrade before any join, e.g. joins counted from the upgrade on whatever op follows, or the upgrade repeated when the text leaves `Slots`), so the floor is per seed and holds at every size; not a lower floor.
