# The sync test binary costs two and a half times its budget
> Summary: osis-sync's `it` binary runs 2,945 G instructions in one process against notes/sync-test-harness.md's 1,200 G; read's judgements dominate, and about half of them are moved by reads of whole permission timelines (`Core::horizon`, `may_rotate`) whose answers rarely change: Fathom's lane (memo early cutoff, or finer timeline reads).
> Priority: normal
> Tags: engine, sync, tests

Measured by `tools/icount` over the binary in one process: 2,945 G (per module: `convergence::` 1,242 G, `sims::` 670 G, `flows::` 475 G, `growth::` 260 G, the rest under 90 G each). A 40-step faulted history plays for about 11 G, and a 3-node differential world costs about as much to build (`introduce`); defaults are seeds (notes/sync-test-harness.md, Measured layers), so cutting them costs coverage, not correctness.

Where a history's cost goes (faulted seed 1, `tools/cpuprof`): read's settle about half, `judge::body` 29% (`read_facts` 14%, `may_log` 13%), memo bookkeeping (stamp reads, frames, `Effects` index) about a sixth, restarts in place a tenth.

What moves read's judgements (clean seed 9, world build then a 40-step play, `Effects` cause counts with `costs` on, timeline reads split by caller in a probe): of 6,070 judgements in the world build, 1,844 were moved by `Core::horizon` (`engine/mod.rs`, reached from `Engine::wrap_blocked`) and 1,066 by `may_rotate` (`rotation/departures.rs`): both read a thing's whole timeline component (`Timelines::get`, stamped `Read::Whole`), which every update of any held role input in the component moves. Both answers (a time bound, a set of roles) rarely change; the judgements reading them are re-run anyway, because a memo's dependants depend on what the memo read, not on its answer.

Causes in the engine (`core/engine`, `core/base/src/memo`):
- **No early cutoff in `Memo`**: a memo recomputed to the same answer still moves every key that read it (`memo::depend` passes the memo's reads on). `wrap_blocked` is a `Cutoff` row per (actor, walk) (`Core::wrap_blocks`), so the timeline fanout above stops there; a body's facts and fate are rows too (notes/engine.md, `Cutoff`; General early cutoff).
- **Whole-component reads for a time bound**: `Core::horizon` reads `Whole` of the actor's and the writer's components to find the next `until`; reading the edges it walks (`Into` per target, as `roles_on` does) would move it only with them.
- **Absent rows read at a bucket stamp** (issues/absent-stamp-fanout.md): `store: local rows` and `catalog kind` move a further fifth of a play's judgements.
- **`body_facts_now` tries every snapshot ever held of each aspect** (`sync/bodies.rs`, `ix.snapshots`) against the body judged: one write synced to one reader joins 20 snapshot pairs after 3 earlier writes, 200 after 30.
- An inbox blob no key here opens (another actor's inbox this node reads, as `introduce`'s profiles give) is tried again at each move of that actor's timeline.

Options on the test side, each a coverage trade (not taken):
- Fewer default seeds (20 per convergence test, 6 per simulation): each faulted seed is about 11 G a play plus its world where no simulation shares it.
- Reproducers in `flows::` each pin a world seed of their own (15, 5, 7, 16, 77, 78, 93 and four 12-digit ones), so each builds a world (about 11 G): moved to `world(0, 3)` they may no longer reach the corner they were shrunk from.
- Fewer distinct differential worlds (a history on world `seed % k`): fewer drawn IDs and tie-breaks (the fixture guard in notes/sync-test-harness.md).
- A cheaper `introduce` (contacts by cards costs about 800 deliveries for 3 nodes).
