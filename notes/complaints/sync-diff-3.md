# Complaints: sync-diff-3
> Summary: a long shrink on the short lane is killed at its CPU cap with no way to resume it there; the quiet check's failure named no state to read; `Script` prints neither Display nor Debug.

- Two shrinks run side by side under `tools/heavy --short` passed the lane's 115 CPU-s cap and were killed; the rerun in a hold started from scratch. A brief asking for a shrink should say it goes in a hold.
- `must-hold bodies with no entry at quiet` printed only (node, S, commit): finding that a pass was still under way took a by-hand probe; the failure now prints S's status at that node.
- `play`'s `Script` implements neither `Display` nor `Debug`, so a hand-written World test cannot print a refused step's note: probing a refusal (`needs Admin`) took `harness::step` by hand. `history::world(seed, n)` gives `n` accounts of one node each, not the differential's shape (`world_of(seed, 2, 3)`): the name invites the wrong one.
