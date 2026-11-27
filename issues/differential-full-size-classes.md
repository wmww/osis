# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential on held-model's stub closure (`Rule::BUILT`) at full size: 35 of 100 seeds fail, by class with what is known of each cause, and the gate seed tools/known_failures.txt lists. Each class to become a hand-written test.
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes change: work from scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in one `tools/heavy` hold (about 275 s wall). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it; a script replays in a scratch test (`differential::holds_on(0, 3, 4, &script, String::new(), false)`, full size).

## Full size (100 seeds, 4 nodes of 3 accounts, 60 steps)
35 fail. By first panic (unshrunk unless said):
- **Reads unlike the reference** (0 5 6 14 28 41 48 53 66 70 85).
- **Reads a thing the model does not hold** (10 11 16 34 73 91).
- **Stub, the model Unread** (2 15 25 31 84; and 81): a node holds a thing as a stub where the model keeps it unread. Hand case: `differential::a_removed_reader_keeps_the_publics_sync_secret_*` (ignored): the removed reader holds the public's sync secret and no step of S bearing it, so kept unread never applies.
- **None, the model Stub** (17 24 52): the model holds a stub of thing 0 the node's sync set lacks.
- **Stub, the model None** (45 86); **None, the model Unread** (65 68); **Unread, the model Stub** (80).
- **A paired node never enters its account** (56 97): in `world_of`'s own setup (`World::pair`, then a run): the paired node holds no role on its account at quiet; the pairing check (`World::pairs_entered`) found it.
- One each: must-hold bodies with no entry at quiet (35); must-hold bodies a caught-up reader lacks at quiet (12).

## Small size
6 seeds: all hold. tools/known_failures.txt lists one gate seed against this issue: 527365123461 ("node 1 reads thing 0 unlike the reference", unshrunk).
