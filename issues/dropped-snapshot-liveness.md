# A dropped snapshot's liveness ignores anchors and tombstones
> Summary: Once a compaction snapshot's body drops, its frontiers go with it (spec/commits.md §5), so `retention::snapshot_live` judges it live iff the state holds a write stamped at or before its `ts`; ts-less records (tombstones, bare anchors) do not count, though spec/commits.md §5 counts anchors as live writes. Counting them instead over-approximates and delays at-most-0 deletes.
> Tags: retention, sync, node, owner-call

Effect today: a snapshot dropped while its only live records were ts-less (compaction supersession, a purge rewrite, keep-at-most with grace) is judged dead at blind-node delete time, so `deletable` (`sync/pass.rs`, `!live`) deletes it at a server without checking that its carrier is present there (spec/sync.md §7). Normally the carrier was uploaded first in the same pass, so the gap is a window; if that upload failed, the label can lose anchors a fresh node needs to place concurrent inserts.

Counting every ts-less record instead (`t.is_none_or(|t| t <= h.ts)`; tier 1 passes with it) is safe for the label but judges a snapshot that dropped dead (at most 0) live whenever the aspect holds later anchors: its delete waits for a carrier snapshot instead of going in the same sync (§5), keeping erased data at blind nodes longer.

Exact options: record at drop, in the commit record (rebuild reads it), whether the dropped body was live then; liveness of a dropped body can only fall afterwards except by a validity flip or redo (to check). Or keep the frontier in the record as header-like metadata, which §5's "index entries derived from it" currently forbids.
