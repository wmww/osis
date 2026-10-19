# MVP run progress
> Summary: Resumption point for the plans/mvp_meta.md run: current wave, per-plan state (not started / running / review / merged / blocked), open escalations, spec edits made during the run, pending owner-calls, and environment facts. Re-read this and `git log` before acting.

## Environment
- 4 cores, 30 GB RAM: run at most ~3 compiling agents at once; stagger compile-heavy spawns.
- Tooling confirmed: Rust stable 1.98, nightly (for cargo-fuzz), cargo-deny 0.20, cargo-fuzz 0.13, cargo-nextest 0.9, Java 21 (TLC).
- Integration branch: `main`. Sub-agent worktrees under `.worktrees/`.

## Current wave
Wave 2 (perm and store from wave 1 still finishing; keys waits for perm).

## Plans
| plan | state | notes |
|---|---|---|
| pre-flight plan diff | merged at cb6f1b0 | |
| workspace | merged at 4b6ec14 | plan folded into notes/architecture.md |
| protocol-spec | merged (spec/wire.md), toplevel-reviewed | plan deleted; owner-call issues/header-list-commitments.md |
| tla-models | models merged at 49c8fd3; findings S1–S10, R1–R7 resolved (spec edits below, issues/reseal-triggers.md) | follow-up agent: write models/tla/run.sh, update both models to the edited text, rerun (list in plans/tla-models.md Progress); target 3 not started |
| core alignment to wire.md | merged | osis-core constants and layouts fixed |
| crypto | merged, reviewed, follow-ups merged at 80b8ad3 | issues/deny-duplicates.md for the integration pass |
| crdt-core | merged, reviewed | plan stays until crdt-seq is done; issues/crdt-path-op-cost.md |
| perm | running (opus, worktree) | |
| test-infra | merged | vectors FC-1 frozen (cbor, tid, gear); notes/testing.md conventions |
| schema | merged at 3461fd8, reviewed | open: unknown-field-survives-set_field test waits for the crdt diff; lock-vs-file write policy undecided (notes/versioning.md) |
| store | merged, reviewed | issues/store-concurrent-readers.md; no decoded-page cache yet |
| crdt-seq | running (opus, worktree) | |
| commit | running (opus, worktree) | |
| label | running (opus, worktree) | |
| proto | running (opus, worktree) | |
| keys | not started | after perm merges |
| node-core, server, transport, large-values | not started | wave 3 |
| sim | not started | phase A after node-core layout; B after node-sync; C wave 5 |
| node-sync, membership-flows, api (first half) | not started | wave 4 |
| apps-e2e, cli, p2p, api (second half) | not started | wave 5 |
| hardening-signoff | not started | wave 6 |

## Open escalations
- None. (TLC findings S1–S10, R1–R7 decided: see Spec edits and Owner-calls pending.)

## Spec edits
- perm review: spec/permissions.md §2 a lowering write by an admin of the member is a self-removal only when it lowers the author's own edge or admin on the member is its only authority (owner-chain or edge-admin authority on the target makes it an explicit demotion, which audits); §5.1 and spec/data-model.md §9: a frontier counter is the last counter received contiguously, inclusive.
- crypto: spec/crypto.md §3 fixes kdf input conventions (two-argument kdf = empty input, tid input = 15 bytes, Ed25519 key from a kdf output = that RFC 8032 seed) and the `kdf("kem", ..)` XOF split (64 bytes ML-KEM `d || z`, then 32 bytes X25519).
- Toplevel review of wire.md: `keyset` carries the epoch's suite ID (spec/data-model.md §9); spec/sync.md §5 says how a member peer authenticates another member's node (its `/reach` dialable key).
- spec/sync.md §3: a projection class whose blob would exceed `MAX_BLOB` splits into several blobs, greedily in aspect-list order (pre-flight found no path under `MAX_BLOB` for a commit touching many aspects). spec/commits.md §1: one delta must fit a blob; the writer refuses the rare struct-of-many-large-registers shape (issues/struct-delta-size.md).

- protocol-spec (filling TBDs into spec/wire.md) also changed: tree-node link content hashes cover child hashes, not the subtree's bytes (spec/data-model.md §6, spec/crypto.md §6; O(change) edits); a recovery key's nonce derives from its seed like a link key's (spec/crypto.md §3); blob AEAD AD is the clear prefix and the inbox AD adds it (spec/crypto.md §5); the token, purge and origin lists go inline-or-link like the aspect list instead of a token cap (spec/commits.md §1); header-list chunk commitments capped (spec/crypto.md §7, owner-call); entry boxes live inside the claim set the step hashes (spec/sync.md §2); a link may carry the sharer node's dialable key and relays for first contact (spec/permissions.md §9).
- crdt-core: spec/crdt.md §3.3 rule 2: a commit-form delta's own source sorts below every other commit ID in element/entry/run arrays (sorting by its real ID was circular: the ID hashes the delta).
- schema: spec/data-model.md §9: `creation`'s exclusive fields 0/1 type `/created` by spec/wire.md §3, not by the missing-field rule (the type system cannot say "exactly one of").
- TLC findings (models/tla; rationale in notes/sync.md, notes/permissions.md, notes/crypto.md, notes/ephemeral.md):
  - S1: spec/commits.md §5: a commit carrying a purge request MUST NOT carry `expires` and its blobs are kept at least until `ts + MEMBERSHIP_KEEP` whatever its deltas' bounds (spec/wire.md §4 bad-input list extended). Affects commit (header validation), node-core (retention), api (a purge and its resets form a commit of their own).
  - S2, S10: spec/commits.md §5 compaction snapshots take the schema's default bounds, never a commit's; spec/sync.md §7 a right holder that must delete a live body and finds no carrier uploads a covering snapshot first; the "member MUST always serve current state" sentence replaced by "live state is never lost" (node state, spec/crdt.md §4.6, or a label entry).
  - S3: spec/sync.md §6 must-not-hold wins every overlap. S4: literal reading kept (no edit). S5: spec/commits.md §5 and spec/sync.md §7 a live body leaves a label only while a covering snapshot, a superset blob of the commit or an identical body stays under it (duplicates need no wait). S6: a reader relays stamped must-hold entries the label lacks. S7: a compactor drops a may-hold body once per (commit, delta set). S8: a purged body is kept as a rewrite, header-only when nothing remains, by whoever drops it; spec/sync.md §3 "an expired class is deleted rather than rewritten". S9: a body holding no delta is covered; a snapshot from a node's whole state covers every body it applied.
  - R1: spec/permissions.md §3 and spec/commits.md §2: a removal or demotion and the rotation of the target's roles it requires are one membership commit; re-seal decisions after a full sync pass, never for a member whose `until` is within `MAX_DRIFT`, boxes to the member's newest keyset the node holds; re-seal delivered by inbox only (label delivery dropped). spec/crypto.md §4: boxing an epoch's secret to a member is encrypting under it (R6). spec/sync.md §3 inbox blob = the parts about G; spec/permissions.md §4 certificate edge writes projected to their edge deltas.
  - R2: spec/permissions.md §4 stranded heartbeat also on a refused claim, wrapped under the newest secret held (spec/crypto.md §5); spec/sync.md §5 such a member is reached by re-seal. spec/crypto.md §3 deposit-seed refresh SHOULD → MAY (it refused stranded heartbeats).
  - R3: spec/crypto.md §4 a grant or re-seal re-writes the history boxes of the epochs it boxes. R4: spec/sync.md §5 re-registration compares (n, nonce) per role against a head epoch the admin holds; otherwise it walks first. R5: spec/crypto.md §5 wrap under the newest current epoch held; a node with no current secret places only its stranded heartbeat. R7: spec/sync.md §2 claim set is as of registration; a re-sealed member opens by sync key.
- crdt-core: spec/crdt.md §4.2, §5.1, §7, §3.2/§3.3 rule 4: nested multi-encoding positions under a parent reset joined order-dependently in the model (members carrying the position reset and "encodings seen are grow-only"). Now: slot members are pruned like any fragment and do not copy the position reset; a member below the register's embedding is dropped; a register's reset below its write goes; a nested `R` below `E_parent` goes. Model updated to match; `model_order_independent_spec_7` checks it.
- crdt-core: spec/crdt.md §5.6, §9: a map put or diff into a key with several live entries diffs against the key's read (join of its live entries), not the lowest entry alone; otherwise `read(join(S, diff(S, v))) == v` failed for concurrent puts. Model updated.
- crdt-core review: spec/crdt.md §2.2: a `Derived(d)` dot orders as `(d.source, d.ctr, i)`, right after the write it embeds (it sorted above every source, so a reset at the same `ts` above the register write kept the embedded characters in some delivery orders). §4.8 names the implied register reset. Model updated (`embedded_chars_order_right_after_their_write`).

## Owner-calls pending
- issues/reseal-triggers.md (residual wrongful re-seal across a fork; members no automatic trigger reaches; recommended: accept for MVP).
- issues/header-list-commitments.md: header-list chunks of commits with more than 16 token secrets carry only author-chain commitments (provisional).
- issues/reseal-triggers.md: two re-seal residues after the TLC fixes: a wrongful re-seal across a fork read out of order (R1), and members no automatic trigger reaches when their deposits are refused (R2); recommended: accept for the MVP, mechanisms listed.
