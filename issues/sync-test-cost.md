# The sync test binary costs about three times its budget
> Summary: osis-sync's `it` binary runs 3,899 G instructions in one process against notes/sync-test-harness.md's 1,200 G; most of it is the differential's fresh world per seed and read's settle (about half of a history: engine reads per body judged, a third of judgements giving the answer they replaced): Fathom's lane for the reads.
> Priority: normal
> Tags: engine, sync, tests

Measured by `tools/icount` over the binary in one process: 3,899 G (`convergence::` 1,741 G, `sims::` 820 G, `flows::` 657 G, `growth::` 333 G). Defaults are seeds, so cutting them costs coverage, not correctness. Each pair of world nodes keeps one connection (spec/sync-opens.md §1 Twin; `growth::each_write_crosses_each_pair_on_one_connection_spec_sync_opens_1`): a write costs about 29 deliveries in the 3-node world, so delivery count is no longer the lever; the engine reads below are.

Where a fresh history's cost goes (clean seed 0 played twice, 39.5 G): read's settle about 47%, `judge::body` 20% of which `read_facts` 11.5% (`sync_body_now`, `body_facts_now`), the engine's `follow` (certified pieces, lists) 7%; building its world and restarting nodes about a sixth. One play judges 3,736 bodies, 1,182 of them to the answer they had (`Effects` cause counts with `costs` on, an equal-rerun count added by hand in `Effects::record`); what moved those: absent store rows read at a bucket stamp (`E/` entries 440, record index rows 430: issues/absent-stamp-fanout.md), views (`read/views.rs`) 306, commit `Meta` 254, timelines 156.

Causes in the engine (`core/engine`):
- **Timelines stamp every touched thing** (`engine/held.rs` `Timelines::moved`): any commit on a thing moves whatever read that thing's timeline, though most readers want one aspect of it; 156 of the seed's judgements, less than the absent-row fanout.
- **`body_facts_now` tries every snapshot ever held of each aspect** (`sync/bodies.rs`, `ix.snapshots`) against the body judged: one write synced to one reader joins 20 snapshot pairs after 3 earlier writes, 200 after 30.
- An inbox blob no key here opens (another actor's inbox this node reads, as `introduce`'s profiles give) is tried again at each move of that actor's timeline.

Options on the test side, each a coverage trade (not taken):
- Fewer distinct differential worlds (a history on world `seed % k`): saves about a quarter of a fresh seed, but fewer drawn IDs and tie-breaks (the fixture guard in notes/sync-test-harness.md).
- A cheaper `introduce` (contacts by cards costs about 800 deliveries for 3 nodes).
