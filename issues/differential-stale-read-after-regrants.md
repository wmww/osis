# Sync differential: a reader keeps an older value after regrants
> Summary: osis-sync `differential::histories_hold_their_closure_plain` fails at small size on main (seed 929925971059 at 21a7971a2, 1 of 6 gate seeds): at quiet node 1 reads thing 0 as v6 where the reference and every other node read v7; its roles match. Seen by a link branch's gate; no link in the script.
> Priority: normal
> Tags: sync, tests

Replay: `OSIS_SYNC_START=929925971059 OSIS_SYNC_SEEDS=1` (deterministic; seed numbers move with commit bytes, so work from the script). Not shrunk yet (`OSIS_SYNC_SHRINK=1`).

- Script (as printed): `New(0), Pair(0), Write(3, 0), Run, Heal, Run, Lossy(Loss { drop: 0, dup: 0, delay: 200, delay_ms: 5000 }), Give(2, 0, Holder::Node(1), Syncs), Partition(0, 2), Skew(3, 0), Strong(1, None, 0), Give(0, 0, Holder::Node(1), Reads), Revoke(0, 0, Holder::Node(1)), Write(3, 0), Run, Run, Give(2, 0, Holder::Node(1), Syncs), Write(3, 0), Run, Write(3, 0), Strong(1, None, 0), Write(0, 0), Strong(1, None, 0), Give(2, 0, Holder::Node(1), Syncs), Strong(1, None, 0), Give(2, 0, Holder::Node(1), Reads), Give(3, 0, Holder::Node(1), Writes), Write(3, 0), Strong(1, None, 0), Give(3, 0, Holder::Node(1), Syncs)`.
- Node 1 (account at Read on thing 0 by a direct path, ticket accepted) holds sync/read secrets through epoch 6, write through 4; v7 is node 3's write after it granted node 1 Writes.
