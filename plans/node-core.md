# Node engine core: identity, clock, commits in and out, atomic apply, pending and parking, retention, undo, listeners
> Summary: Implement the local engine in `osis-node` without networking: node identity and local things, the HLC with corrected clock, turning local ops into signed commits (schema defaults, counters, dot form, MAX_BLOB splitting), receiving commits (signature, dedup, certificate chains via perm, pending reasons, parking, drift cap, atomic apply in one store transaction, membership before content, listeners after), per-delta validity and un-merge, retention bookkeeping (deaths, bounds, covered, keep-at-most drops), expiry, purge requests, compaction snapshots, undo, synthetic aspects, move/import, diagnostics, engine events. Defines the module layout the two other node plans fill.
> Tags: commits, crdt, permissions, storage, tests

Crate: `osis-node` (modules `engine/`, `apply/`, `retention/`, `undo/`, `identity/`, `events/`; `labeling/`, `sync/` and `flows/` belong to plans/node-sync.md and plans/membership-flows.md and are created as empty modules here). Depends on: core, crypto, crdt, schema, commit, perm, keys, store. Unblocks: node-sync, membership-flows, api, sim.
Spec: spec/commits.md (all), spec/crdt.md §2.2 (HLC, drift), §4.5–§4.8, §8, §9; spec/versioning.md §2 (parking); spec/permissions.md §4–§5, §7–§8 (as consumer of perm); spec/data-model.md §1 (creation records, colliding records), §8–§9 (synthetic aspects). Notes: notes/api.md (listeners fire locally too, diagnostics, move resolution), notes/crdt.md (hints: undo stack derived, repair via listeners only if deterministic), notes/local-store.md. Spec trumps this plan.

## Deliverables
- Identity: node seed → key actor, node thing with `/created`, `/node`, `/keys`; creation of things (creation record, tid, owner); colliding record rule (keep held, diagnostic).
- Clock: HLC per spec/crdt.md §2.2 over `Clock` + offset from node-sync; park commits more than `MAX_DRIFT` ahead and re-examine as time passes.
- Writing: a `Mutation` collects ops across things; resolve against local state (crdt ops, diff with the schema `View`), one delta per aspect, counters per (aspect, node) durable before signing, node or commit dot form, retention from schema defaults with overrides, expiry defaults, schema table, chunk list (plans/large-values.md plugs in), `CommitBuilder`; split into several commits when over `MAX_BLOB` (not atomic, documented); sign; apply locally (listeners fire for local writes too); hand to `labeling/` (a trait hook until node-sync lands).
- Receiving: `ingest(commit bytes, deltas...)`: signature, dedup by commit ID, prefix-vs-header check (when framed), delta hash check, range checks; pending reasons (chain certificates missing, `/created` unknown, parked part, drift, atomic apply waiting for deltas/pages); re-examination triggers (new certificates, start/stop syncing a thing, time); parked commits kept as bytes with header.
- Atomic apply: one `Store` transaction joining every readable delta of the commit, membership commits before content, engine events emitted after commit; per-delta validity from perm; invalid delta un-merged (re-join of held bodies via crdt), later re-grant re-merges.
- Retention: per body first/last death from the crdt change summary; keep-at-least/at-most bounds; `covered` by held snapshots (join-identity test on canonical bytes); keep-at-most drop in the killing transaction (at most 0) or at the bound; `nobody`/`admin`/`author`/`writer` rights via perm at request time; purge request application (value-less from then on, drop bodies incl. snapshots, re-snapshot trigger); expiry at T (value-less, drop body); snapshot production for an aspect (writer) with paging through store/large-values; delete-at-blind-node obligations recorded for node-sync (a queue of (label, blob, time) the sync layer executes).
- Undo: derived stack from the actor's own commits in scope; undo commits per crdt §4.6; undo buffer kept in the store unit; admin view of others' changes.
- Synthetic aspects `/tid`, `/aspects`, `/groups` (closure over `/group` writes, maintained incrementally), `/created` guaranteed.
- Move: import commit production (origins, re-sourcing through crdt), `/was` and `/moved` writes, the "do not import while holding a copy" guard; resolution view for reads (perm's rule) applied by the engine to values returned and to roster reads.
- Engine events channel (typed) and diagnostics (structured, deduped, rate-limited per peer); the `osis` API builds on these.
- A `LocalPeer` test harness: two engines exchanging commit bytes directly (the simulator's seed; plans/sim.md grows it).

## Steps
- [ ] Module layout committed early (so node-sync and flows can start); identity, clock, store wiring, creation records.
- [ ] Writing path end to end (ops → commit → local apply → events) for all encodings; MAX_BLOB split.
- [ ] Receiving path: verification, pending/parking, atomic apply, events; two-engine convergence tests under random delivery (crdt differential at the node level).
- [ ] Validity and un-merge with perm; the Bob revocation scenario and Carol variant as tests (notes/permissions.md) at the engine level with hand-fed membership commits.
- [ ] Retention, expiry, purge, compaction snapshots, undo; tests per spec/commits.md §5–§7 sentence.
- [ ] Synthetic aspects, move/import, diagnostics; version-skew unit tests (unknown encoding parks the commit, re-examined after "upgrade" flag flips).

## Done when
Two engines connected by `LocalPeer` converge for every encoding, honour revocation, retention, expiry, purge and undo per the tests; node-sync and flows build on the committed module layout; notes/overview.md status updated. Delete this plan, folding engine notes into a new notes/node.md.

## Progress
