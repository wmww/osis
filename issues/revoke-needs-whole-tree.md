# Revocation gaps left after receipts-only reads
> Summary: a demotion's frontier is the revoker's own receipts (spec/permissions.md §5.1). Receipts-only reads (built: notes/sync.md Receipts-only reads) let a node that holds part of a tree read the rest's commit headers before stamping, so a phone can remove a holder without losing their edits. Still lost: writes at saved peers the remover cannot reach, writes that reached another holder only over a direct peer path. Writer witnesses would close most of both.
> Tags: permissions, sync, spec

## What is built
A group set to log only (`SyncMode::LogOnly`, engine `receipts_only`) is not synced; `set_role`'s pre-sync for a removal or lowering opens its labels, fetches commit blobs only, records verified headers as received, by commit ID (spec/permissions.md §5.1 is header-level) and applies only the role commits that carry the group's secrets. Nothing is uploaded, deleted or placed under those labels (osis test `removal_from_partial_node_keeps_unheld_edits_spec_permissions_5_3`, sim scenario `demotion_receipts`).

## Remaining gaps
- **Unreachable peers**: a label whose saved peer the remover cannot reach at removal time is not read (`set_role` waits for it, `set_role_now` loses the holder's unseen edits there).
- **Peer-only edits**: edits that reached another holder only over a direct peer path and never a saved peer.
- **Compaction**: no gap for the receipts-only read since headers count by commit ID (no contiguity): the holder's commits whose headers the host deleted are carried by a covering snapshot (a valid one vouches; the holder's own is listed by ID like the rest). A late joiner that got the holder's writes only through a snapshot lists none of them (snapshot frontiers are no receipts); the snapshot vouches for them.
- **Linked headers**: a header whose lists go by link is not recorded (its pages are not fetched).
- **Writer witnesses** (follow-on, not built): every writer's ordinary delta carries the per-author received frontier its compaction snapshots already carry (spec/crdt.md §8 `Frontiers`), and a removed holder's write counts if the remover's frontier covers it or a valid writer's delta stamped before the cutoff shows it received it, witnesses counted outward from the remover's record (a least fixpoint, so a later-removed witness bootstraps nothing). Writers only: a reader witness would let a reader and an ex-writer combine into write power. Edge writes keep today's rule (the self-witness hole and non-settling histories of notes/permissions.md live there). The receipt record is the shared input. Inherent floor: the holder's trailing edits that no writer saw before the cutoff look exactly like a backdated forgery and are hidden until re-grant.

Other uses of receipts-only reads, not built: activity views over groups a node does not hold, admin nodes that hold nothing, header-level forensics.

Rejected along the way: trusting the author's timestamp for content (a removed writer plus a colluding reader could inject backdated edits that honest writers re-stamp: "readers only read" breaks); scoped removals via `until` (needs a node holding the tree to finalize).
