# CRDT spec vs design review
> Summary: Review items (2026-10-16) written against the now-deleted plans/crdt-spec.md that spec/crdt.md does not yet cover.
> Tags: crdt

The design review and spec/crdt.md were written in parallel. Fold into the spec:
- Expiry at T (notes/crdt-sync.md, Retention): encode the register floor T in state and snapshots; nested payloads of an expired enum case.
- Snapshot deltas carry per-author dot frontiers for the aspect (notes/sync.md, Compact); spec §8 does not.
- Drift cap: review parks commits stamped beyond the cap until local time catches up; spec §2.2 joins them and only stops the clock following. Pick one.
- Per-commit author table and per-AK type hash/revision in the header (review) vs the spec's sources table (§2.4): reconcile.
