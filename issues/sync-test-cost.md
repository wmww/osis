# The sync test binary costs about twice its budget
> Summary: osis-sync's `it` binary runs 2,534 G instructions in one process against notes/sync-test-harness.md's 1,200 G; most of it is the differential's fresh world per seed and read's settle (engine reads whose memo stamps move with every commit on a thing): Fathom's lane for the reads.
> Priority: normal
> Tags: engine, sync, tests

Measured by `tools/icount` over the binary per module (notes/sync-test-harness.md, Measured layers): `convergence::` 1,172 G (20 faulted histories played twice, 20 clean once, the handed-history oracle tests), `sims::` 574 G (9 scenarios x 6 seeds), `flows::` 453 G, `growth::` 183 G. Defaults are seeds, so cutting them costs coverage, not correctness.

Where a fresh history's cost goes (cpuprof, clean seed 0): building its world about a quarter (`history::introduce`, about 950 deliveries; shared in one process by the convergence tests and simulations of the same seed); read's settle about 60%, of which `read::judge::body` about half.

Causes in the engine (`core/engine`):
- **Timelines stamp every touched thing** (`engine/held.rs` `Timelines::moved`: `touched` and `changed()` alike): any commit on a thing moves whatever read that thing's timeline, though most readers want one aspect of it (its epochs, its roles). Readers in sync's facade: `sync_bodies` (through `thing_sync`, `owned_sync_ids`, `epochs`), `read_facts`, inbox opens (`epochs`, `account_kems`), `own_commits`. Scaling: a reader's own write to its account's group re-judges every body of every thing it reads (keep.rs's `one_write_after` shape).
- **`body_facts_now` tries every snapshot ever held of each aspect** (`sync/bodies.rs`, `ix.snapshots`) against the body judged: one write synced to one reader joins 20 snapshot pairs after 3 earlier writes, 200 after 30.
- **Signatures checked about 2.6 times per commit per node** (issues/signature-checked-per-receiver.md).
- An inbox blob no key here opens (another actor's inbox this node reads, as `introduce`'s profiles give) is tried again at each move of that actor's timeline.

Options on the test side, each a coverage trade (not taken):
- Fewer distinct differential worlds (a history on world `seed % k`): saves about a quarter of a fresh seed, but fewer drawn IDs and tie-breaks (the fixture guard in notes/sync-test-harness.md).
- A cheaper `introduce` (contacts by cards costs about 950 deliveries for 3 nodes).
