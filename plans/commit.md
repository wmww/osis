# Commit crate: headers, signatures, delta hashes, projections, purge rewrite, tokens
> Summary: Implement spec/commits.md in `osis-commit`: the canonical header (layout from plans/protocol-spec.md), commit ID and signature, kinds and markers, dot forms, aspect list with ranges, retention, expiry and schema index, chunk list with token hashes, purge request, undoes, frontier, aspect list and chunk list inline or by link, delete-token salt and hashes with levels, the origins table for imports; structural verification of a received commit; the `CommitBuilder`; projection into blobs by (readable subset, retention class); purge rewrite.
> Tags: commits, crypto, tests

Crate: `osis-commit`. Depends on: osis-core, osis-crypto, osis-crdt (delta range checks, delta bytes), osis-schema (retention types, schema table). Unblocks: label (blob prefix needs the header's expiry and token hashes), perm (edge write keys), node-core.
Spec: spec/commits.md (all), spec/crdt.md §2.3–§2.4, spec/crypto.md §2, §6–§7, spec/permissions.md §5.1 (frontier shape), §7 (import origins). Notes: notes/crdt.md (commit floor ~300 B), notes/sync.md (projection, token levels). Spec trumps this plan.

## Deliverables
- `Header` type and canonical encode/decode (field order per protocol-spec; parks unknown format versions above ours per spec/versioning.md §2; rejects malformed), `CommitId = BLAKE3(header without signature)`, sign/verify under `"osis v1 commit"`.
- Kinds: content / membership; markers: compaction snapshot, import (with origins table), roster snapshot; validity of kind/marker/field combinations (§2: a commit spanning kinds is invalid; membership commits never carry `expires`; snapshots and imports have empty ranges; frontier only on demotions).
- Aspect entries: `(tid, ak, [lo, hi), retention, expires?, schema index?, delta hashes[])`; `Retention { purgeable_by, keep_at_least, keep_at_most }` with the §5 bounds grammar (absolute, relative, both; relative at-most only under `writer`); the fixed retention table for membership-class aspects and `/created`.
- Delta hash `kdf("delta", dedup secret, delta bytes)`; `verify_deltas(header, deltas, dedup secrets)`: hash match, range check through osis-crdt (§2.3), one delta per aspect for content, several allowed for membership sharing a range; `expires > wall_ms(ts)`.
- Token model: token secrets by level per delta's retention (level 1 admin, 2 author-chain write secret, 3 thing write secret; omitted for imports at level 2), header salt, token hashes with levels (cap from protocol-spec), chunk list entries with their token hashes in commit order; a `TokenSecrets` input trait so keys/node supply secrets.
- `CommitBuilder`: given ts, author node, actor, dot form, deltas per aspect with their ranges, retention per aspect (schema defaults with per-commit override), expiry, schema table, chunks, purge request, undoes, frontier → header + signature; links the aspect and chunk lists above `CHUNK_THRESHOLD`.
- Projection: `project(commit, readable: impl Fn(&Delta) -> bool, class_of: impl Fn(&Delta) -> RetentionClass) -> Vec<Projection>`, each the header plus the deltas of one (readable subset, retention class incl. expiry and token set) with the prefix inputs (expiry, commitments) the blob needs (osis-label frames it); strict-subset detection helper for convergence.
- Purge rewrite: same header, fewer deltas; `Purged` marker per missing delta; a receiver treats a missing delta it has not seen as not held.
- Import support: origins table encode; re-sourcing of dots is crdt's job (provide the `Commit(origin)` source and rank rule there or here; keep one place).
- Undo linkage `undoes`.

## Steps
- [ ] Header types + canonical encoding (provisional field order behind one module if protocol-spec is not merged yet; switch and freeze vectors when it is); CommitId; sign/verify.
- [ ] Retention grammar, fixed tables, expiry rules; validation of kinds/markers.
- [ ] Delta hashing and verification with crdt; token hashes/levels; chunk list.
- [ ] Builder with list overflow; projection; purge rewrite; origins.
- [ ] Fuzz target for the header decoder (test-infra); vectors for a minimal content commit, a membership commit, a snapshot, an import; proptest: encode/decode round trip, projection delta sets partition the commit, every projection verifies alone.

## Done when
node-core builds and verifies commits only through this crate; vectors frozen; size test: a minimal content commit header + one register delta ≤ the floor notes/crdt.md states (≈300 B before encryption, tier-2 budget). Delete this plan, folding layout notes into notes/crdt.md or notes/sync.md.

## Progress
