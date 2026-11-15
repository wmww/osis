# The sync test binary costs about three times its budget
> Summary: osis-sync's `it` binary runs 3,094 G instructions in one process against notes/sync-test-harness.md's 1,200 G; most of it is the differential's fresh world per seed and read's settle (judge::body about a quarter of a history): Fathom's lane for the reads.
> Priority: normal
> Tags: engine, sync, tests

Measured by `tools/icount` over the binary in one process: 3,094 G; per test alone (`tools/pertest.py`, each test its own process) `convergence::` 1,691 G, `sims::` 1,337 G, `flows::` 685 G, `growth::` 297 G. Defaults are seeds, so cutting them costs coverage, not correctness. Each pair of world nodes keeps one connection (spec/sync-opens.md §1 Twin; `growth::each_write_crosses_each_pair_on_one_connection_spec_sync_opens_1`): a write costs about 29 deliveries in the 3-node world, so delivery count is no longer the lever; the engine reads below are.

Where a history's cost goes (three faulted seeds in one process, cpuprof): read's settle 46%, `judge::body` 26% (`may_log` 12%, of it the sync store's `held_blobs` 8%; `read_facts` 7%), the shared world 31% (`introduce`), `Effects::due`'s log reads 10%, `follow_certificates` 9%. Judgements, by `Effects` causes with `costs` on: building `history::world(0, 3)` judges 4,648 bodies (peer record index rows 518, `commit_blobs` 414, `timelines: into` 396, aspect state rows 369, first judgements 339, `secrets` 257, the store's `X` and `E` local rows 210 and 164); clean seed 0 played twice judges 16,796.

Causes in the engine (`core/engine`):
- **Timelines stamp every touched thing** (`engine/held.rs` `Timelines::moved`): an edge change on a thing moves whatever read the edges into it (`timelines: into`, 396 of the world's judgements); a whole-component read (`timelines: whole`) moves `life`'s lost-access and role-duty keys at every role change.
- **`body_facts_now` tries every snapshot ever held of each aspect** (`sync/bodies.rs`, `ix.snapshots`) against the body judged: one write synced to one reader joins 20 snapshot pairs after 3 earlier writes, 200 after 30.
- An inbox blob no key here opens (another actor's inbox this node reads, as `introduce`'s profiles give) is tried again at each move of that actor's timeline.

Options on the test side, each a coverage trade (not taken):
- Fewer default seeds (20 per convergence test, 6 per simulation): each faulted seed is about 11 G a play plus its world where no simulation shares it.
- Reproducers in `flows::` each pin a world seed of their own (15, 5, 7, 16, 77, 78, 93 and four 12-digit ones), so each builds a world (about 11 G): moved to `world(0, 3)` they may no longer reach the corner they were shrunk from.
- Fewer distinct differential worlds (a history on world `seed % k`): fewer drawn IDs and tie-breaks (the fixture guard in notes/sync-test-harness.md).
- A cheaper `introduce` (contacts by cards costs about 800 deliveries for 3 nodes).
