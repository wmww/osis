# Engine: suspect flags and repair
> Summary: Where the engine flags an aspect it may have computed from less than another holder (`retention/suspect.rs`, `q/`), what clears a flag (bodies back, dormant under a later valid snapshot, never for pending expiry), how heartbeats carry flags with state digests and a writer re-snapshots (`sync/pass/beats.rs`), the accepted limits, the rejected settling rules with their seeds, and how the order oracle treats flagged aspects. Rules: spec/permissions.md §4, spec/sync.md §7, spec/commits.md §5; reasons: notes/convergence-study.md §3. Not here: what drops the data (notes/engine-retention.md, notes/engine-validity.md).

## The limit it backstops
Every writer dropped what a reader kept, so no writer can mend it and the reader's relay meets the tombstone: they read apart until the next write of that data (spec/requirements.md Deterministic). Rejected: a reader deposit, a new rule that lets a reader put back a value a writer deleted. The flag only asks for a repair; no read or state depends on it.

## Raising (`suspect::raise`)
- `Why::Uncovered`: `retention::uncover` with parts lost; a body dropped while invalid (a right-less drop) that turned valid (`retention::valid_again`); a waiting part gone for a purge with a page away (`retention::strip_purged`). The aspect reads the value the purged write superseded until a copy or a snapshot repairs it.
- `Why::PendingExpiry`: a part pending at its expiry (`pending_drops` at pend, parked copies included; `strip_pending` from the T timer). Only that aspect is flagged.
- A flag lists the bodies it is about ((commit, ai, `Why`) entries in the `q/` record). Each entry goes when that body is held again (`body_back` from `late_parts`); the flag goes with its last entry.

## Settling
- A Flip or Uncovered entry is dormant while a held snapshot valid here is stamped after its commit, judged when `suspects` is read (`suspect::dormant`, `receipt::settled`), so a settling snapshot that turns invalid shows the flag again (alike seed 4208). No frontier test: pruned sessions leave nothing to test, and it was never exact (a writer that applied the delta, then dropped it, reached it carrying nothing).
- Limit, accepted (Tess: simple and consistent over rare shapes): a snapshot whose author never received the delta settles the flag too, so a node holding the delta reads richer, unreported, until a writer holding it compacts (it is uncovered there, and a live write leaves only with a carrier) or a copy arrives and joins (`takes_late`).
- A PendingExpiry entry is never dormant (it goes only with its thing, `forget`): its part's writes reach this node only as a snapshot's copies, and no test on held snapshots tells whether one repaired it. It yields to any flag raised after it (`suspects_under`: most recent first), so it cannot keep a newer one out of a heartbeat.
- Rejected settling rules:
  - clearing on any later-stamped snapshot (alike seed 4108: a writer's ordinary compaction carrying nothing of the part cleared it, leaving the divergence silent);
  - a listing valid snapshot (seed 5288: the writer lacked the snapshot keeping the entry the part wrote into, so its un-merge took the entry whole and its snapshot after T listed the part carrying nothing of it; the reads differed);
  - a listing one carrying a write of the part (5288 with a second put in the same commit: the snapshot held the part's write value-less in a key-erased record, spec/crdt.md §4.7, outside the entry it wrote, and the reads still differed; also commit-level writes of one delta share a dot, so no dot test sees a partial carry).

## Repair (node-sync)
- The heartbeat lists the flags of the label's closure with `Engine::state_digest` (16 B), the most recently flagged first, at most `MAX_HEARTBEAT_SUSPECTS` (32); one heartbeat commit per distinct list. A node holding no state of a flagged aspect reports it too.
- `repair_suspects` (after `reseal`) reads each node's newest heartbeat commit's own part (`Engine::part_value`); a writer of the thing with a different digest writes `Engine::snapshot`, unless it already snapshotted from this same state for that node (`repair_state`, in memory: a report no snapshot can settle, order seed 5288, costs one snapshot per state per reporting node, one more per restart; issues/suspect-repair-per-launch.md). A writer with the same digest only logs it. Every judged entry is a `DiagnosticKind::Repair`, so silent repairs hide nothing. `SyncEngine::repaired` (in memory) keeps it to once per heartbeat entry.
- Not built: the label-level `held`/`state` set-hash digests (notes/convergence-study.md §3, detection of unknown divergence).

## Oracles
The order, parts and new-node oracles excuse the reads and states of an aspect a part may have waited at its expiry on (Tess: a part expired before a node could apply it), decided from the history, never from the node's flags: `order::waited_at_expiry` over the node's deliveries (a part is ready once its pack and every pack of the held set made before it came whole, none stamped ahead of the clock; one ready on arrival, or ready at a later arrival before its expiry, did not wait at it; any other part of a commit expired by then may have). A node flagging an aspect outside that set fails (`live_write_lost`). Everything else is compared exactly.
