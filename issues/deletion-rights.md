# Deletion: who may delete what, and when it takes effect
> Summary: Every open deletion question in one place, to be settled together: hard-delete rights at blind nodes (constraints tension 8), who may purge history, grace-period default, the partial-purge debounce bound, default compaction policy for `undefined` retention, and the local erasure mechanism for forward-secure deletion. Collected 2026-10-11; owner wants these resolved in one session.
> Tags: sync, security, permissions, crdt

Decided already (do not reopen): three retention classes, purge granularity one (commit, aspect) delta, no fingerprint after purge, forward-secure deletion as a requirement, read access never deletes at a blind node, rotation decoupled from deletion (notes/constraints.md, notes/crdt-sync.md, notes/sync.md).

## 1. Hard delete at blind nodes (constraints tension 8)
Label keys per role are proposed in notes/sync.md: upload for readers, soft retire for writers, hard delete for admins. A blind node checks only signatures, so whoever holds hard delete can wipe the label. Open: what a writer's purge does there.
- Admin-only hard delete (agent's recommendation). A writer's purge is a soft retire; the content leaves the blind node at the end of the grace period, or earlier if an admin shortens it. Backups are safe from every non-admin. The deletion constraint then needs a note that purge at blind nodes is delayed by the grace period.
- Writers hard delete. Purge takes effect at once. Any writer, or any stolen writer device, can wipe a backup label.
- Middle: a separate, shorter purge grace for writer-flagged retires. Delays purge by hours rather than weeks, but a vandal can flag everything.
Related: a writer's soft retire covers the whole label (the blind node sees no finer structure); any writer may un-retire within the grace period; per-uploader pseudonymous keys for mixed-owner labels would let uploaders retire only their own entries at the cost of leaking uploader count; rate limiting soft retires per label stays a heuristic.

## 2. Who may purge history (notes/permissions.md, notes/crdt-sync.md)
An explicit purge of a preserved aspect's history must exist (secret pasted into a versioned doc), but letting any editor purge lets a vandal hide what they changed. The purge record stays visible (who, when, which AK), which deters but does not restore. Candidates: purge right follows the original author of the content; admin-only; a schema knob per AK; granular flags in commits. Enforcement is only against honest nodes either way. Owner: possibly overcomplicating, decide with a concrete app. Must agree with item 1: a writer who may purge locally but not hard-delete remotely gets the grace-period delay.

## 3. Grace-period default
Per-label policy set by admins and carried in the retire (constraints tension 4). The default is unset. Trades backup safety against how long purged content lingers at blind nodes under item 1.

## 4. Partial-value purge debounce
Purging part of a value (a paragraph, a map entry) needs a snapshot of the surviving live content first, so the resetting node batches behind a debounce. The deletion constraint holds only within that bound, and the bound is not set (notes/crdt-sync.md, Retention).

## 5. Default compaction policy
`undefined` retention lets nodes drop superseded bodies by local policy, and compaction is what drops them at blind nodes. When to compact, and which member does it, is open (notes/sync.md). Interacts with item 1 since compaction is a soft retire.

## 6. Local erasure
Forward-secure deletion requires that a node which deleted honestly and is compromised later yields nothing: crypto-shredding (per-blob keys, now in the design, dropped on delete) or secure delete in the storage backend, plus dropping every local reference (links, chunk index, tombstones, index entries). Marked out of scope for now but must be designed in (notes/constraints.md). Decide which mechanism each storage backend relies on and what "dropped" means for wraps held by other labels.
