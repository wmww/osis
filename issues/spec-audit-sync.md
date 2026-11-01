# Spec audit 2: node sync rules where code and spec part
> Summary: Open decisions and code gaps from part 2 of the spec audit (spec/sync.md §3, §6, §7, §9): ephemeral supersession skips core keys only in code, tombstone no-reupload keyed per commit, decline scope, MAX_BLOB split order, misplaced upload pacing.
> Tags: spec, node-sync, ephemeral

Spec-side wording was fixed on branch spec-audit-2 (frontier chunks as the same blobs, contact card, "receiver keeps" until judgeable, stale node cards, clock samples, ephemeral held-at-host sources, relay-only memory order).

## Decisions
- **Ephemeral supersession skips core keys.** `engine/src/ephemeral/remote.rs` `eph_superseders` returns `None` for a part on a core key (`is_core_key`: `placed.0~`), so such commits are never dropped as superseded; spec/sync.md §9 has no exception and says the drop happens at every node. A conforming node without the exception drops them, and reads differ once the superseding write is removed or undone. `note_written` (same file) does supersede unsent own writes on core keys, so the code disagrees with itself. No recorded reason (added in 1fdee514). Either write the exception into §9 (and into `note_written`) or remove it. Convergence, narrow.
- **Decline scope.** spec/sync.md §3: declining leaves the commit unapplied "in every blob carrying it, for good". `state.declined` is checked only on inbox ingest (`node/src/sync/inbound.rs`); the same commit as a closure blob or a sibling's copy still applies, and `admits` treats a held commit as admitted. Decide whether a decline on one device holds against a sibling's acceptance; local behaviour only.
- **MAX_BLOB split order.** spec/sync.md §3 "greedily in aspect-list order" does not order several deltas of one aspect nor say "fits" means the padded, framed blob. `commit/src/project.rs` `project_resolved` splits in stored part order, measuring `osis_crypto::blob_len` with commitments. Two implementations could split differently (extra blobs, no divergence of state). State both.

## Code gaps (spec is right)
- **Tombstone no-reupload rule keyed per commit.** spec/sync.md §6: no upload of "a body a delete removed from the label" while its live writes are carried. `state.deleted` is keyed by (label, commit) (`node/src/sync/state.rs` `remove_entry`, checked in `pass/mod.rs`), so after one body of C is deleted, another must-hold body of C (another class or split) is withheld too while its writes are carried. Weaker, not unsafe. Key it by body (commit and delta set).

## Misplaced
- §9 "While every connection where a label is open has an upload of an own ephemeral entry under it unanswered, the node's later writes ... are not sent" is pacing (local policy), not interop; move to notes/ephemeral.md or mark it local policy.

## Not audited
Must-hold "established covered/uncovered" in detail (`must_hold`, `snapshot_carries`); closure tagging and retag; inbox re-send timing; the §9 cap decode bound, ephemeral record lifetime, cover splitting and the caught-up condition before compacting; partial-node repetition.
