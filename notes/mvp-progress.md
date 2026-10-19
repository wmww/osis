# MVP run progress
> Summary: Resumption point for the plans/mvp_meta.md run: current wave, per-plan state (not started / running / review / merged / blocked), open escalations, spec edits made during the run, pending owner-calls, and environment facts. Re-read this and `git log` before acting.

## Environment
- 4 cores, 30 GB RAM: run at most ~3 compiling agents at once; stagger compile-heavy spawns.
- Tooling confirmed: Rust stable 1.98, nightly (for cargo-fuzz), cargo-deny 0.20, cargo-fuzz 0.13, cargo-nextest 0.9, Java 21 (TLC).
- Integration branch: `main`. Sub-agent worktrees under `.worktrees/`.

## Current wave
Wave 3 (transport, large-values, node-core, server running); wave 2 integration pass running.

## Plans
| plan | state | notes |
|---|---|---|
| pre-flight plan diff | merged at cb6f1b0 | |
| workspace | merged at 4b6ec14 | plan folded into notes/architecture.md |
| protocol-spec | merged (spec/wire.md), toplevel-reviewed | plan deleted; owner-call issues/header-list-commitments.md |
| tla-models | models merged at 49c8fd3; findings S1–S10, R1–R7 and (round 2) S11–S15, R8, R9, residue 1 resolved (spec edits below, issues/reseal-triggers.md) | follow-up agent: update both models to the round-2 text and rerun (plans/tla-models.md Progress lists the changes and expected flips); target 3 not started |
| core alignment to wire.md | merged | osis-core constants and layouts fixed |
| crypto | merged, reviewed, follow-ups merged at 80b8ad3 | |
| crdt-core | merged, reviewed | plan stays until crdt-seq is done; issues/crdt-path-op-cost.md |
| perm | merged, reviewed | issues/ledger-late-audit.md, issues/perm-eval-cost.md |
| crdt-core | merged, reviewed | plan folded into notes/crdt.md with crdt-seq; issues/crdt-path-op-cost.md |
| perm | running (opus, worktree) | |
| test-infra | merged | vectors FC-1 frozen (cbor, tid, gear); notes/testing.md conventions |
| schema | merged at 3461fd8, reviewed | open: unknown-field-survives-set_field test waits for the crdt diff; lock-vs-file write policy undecided (notes/versioning.md) |
| store | merged, reviewed | issues/store-concurrent-readers.md; no decoded-page cache yet |
| crdt-seq | merged, reviewed | crdt plans folded into notes/crdt.md; issues/crdt-seq-linearization-cost.md, issues/crdt-run-amplification.md (snapshots) |
| commit | merged, reviewed | plan stays until vectors freeze and node-core uses it; owner-call issues/token-admin-secret.md; issues/commit-delta-content-rules.md |
| label | merged, reviewed | issues/tree-reader-bounds.md; tree reader to be unified with osis-commit's at integration |
| proto | merged, reviewed | plan stays until server and node-sync are thin drivers |
| keys | merged, reviewed; follow-up running (established epochs, issues/keys-established-epochs.md) | plan stays until flows and node-sync use it |
| crdt-seq | running (opus, worktree) | |
| commit | running (opus, worktree) | |
| label | running (opus, worktree) | |
| proto | running (opus, worktree) | |
| keys | running (worktree) | steps 1–5 landed; plan stays until membership-flows and node-sync use it |
| node-core | review | all steps done; plan folded into notes/node.md; reviewer running; issues/node-core-gaps.md |
| transport | merged, reviewed | plan stays until server and node run over both transports |
| large-values | library parts merged, reviewed | node integration in wave 4; issues/large-value-seek.md |
| server | merged, reviewed; transport wiring running | plan stays until node-sync and sim run through it |
| proto | review | review fixes done (label coupling resolved) |
| keys | running (opus, worktree) | |
| node-core, server, transport, large-values | not started | wave 3 |
| sim | phase A merged | found issues/node-revoke-divergence.md; B after node-sync; C wave 5 |
| node-sync, membership-flows, api (first half) | not started | wave 4 |
| apps-e2e, cli, p2p, api (second half) | not started | wave 5 |
| wave 2 integration pass | merged | issues/tree-unify.md and base64url merge for the wave 3 pass |
| hardening-signoff | not started | wave 6 |

## Open escalations
- None. (TLC findings S1–S10, R1–R7 and round 2 S11–S15, R8, R9 decided: see Spec edits and Owner-calls pending. Wave 4 spawns must read issues/keys-established-epochs.md.)

## Spec edits
- node-core review: spec/permissions.md §7 an import may be split into several import commits, one per origin commit, written in one local transaction (decided by the coordinator).
- transport review: the §10 quic paragraph adds no 0-RTT, mandatory client auth, RFC 8410 Ed25519 SPKI and `ed25519` scheme only, SNI ignored, URL form (port required, IPv6 in brackets), a server dialing a server uses its address key, the dialer closes.
- transport: spec/sync.md §10 defines `quic://host:port` (QUIC v1, TLS 1.3, ALPN `osis`, RFC 7250 raw Ed25519 keys both sides: server = address key, client fresh per connection; each sync session on a client-opened bidirectional stream). Filled an unspecified interop gap; no frozen bytes touched.
- perm review: spec/permissions.md §2 a lowering write by an admin of the member is a self-removal only when it lowers the author's own edge or admin on the member is its only authority (owner-chain or edge-admin authority on the target makes it an explicit demotion, which audits); §5.1 and spec/data-model.md §9: a frontier counter is the last counter received contiguously, inclusive.
- crypto: spec/crypto.md §3 fixes kdf input conventions (two-argument kdf = empty input, tid input = 15 bytes, Ed25519 key from a kdf output = that RFC 8032 seed) and the `kdf("kem", ..)` XOF split (64 bytes ML-KEM `d || z`, then 32 bytes X25519).
- Toplevel review of wire.md: `keyset` carries the epoch's suite ID (spec/data-model.md §9); spec/sync.md §5 says how a member peer authenticates another member's node (its `/reach` dialable key).
- spec/sync.md §3: a projection class whose blob would exceed `MAX_BLOB` splits into several blobs, greedily in aspect-list order (pre-flight found no path under `MAX_BLOB` for a commit touching many aspects). spec/commits.md §1: one delta must fit a blob; the writer refuses the rare struct-of-many-large-registers shape (issues/struct-delta-size.md).

- protocol-spec (filling TBDs into spec/wire.md) also changed: tree-node link content hashes cover child hashes, not the subtree's bytes (spec/data-model.md §6, spec/crypto.md §6; O(change) edits); a recovery key's nonce derives from its seed like a link key's (spec/crypto.md §3); blob AEAD AD is the clear prefix and the inbox AD adds it (spec/crypto.md §5); the token, purge and origin lists go inline-or-link like the aspect list instead of a token cap (spec/commits.md §1); header-list chunk commitments capped (spec/crypto.md §7, owner-call); entry boxes live inside the claim set the step hashes (spec/sync.md §2); a link may carry the sharer node's dialable key and relays for first contact (spec/permissions.md §9).
- crdt-core: spec/crdt.md §3.3 rule 2: a commit-form delta's own source sorts below every other commit ID in element/entry/run arrays (sorting by its real ID was circular: the ID hashes the delta).
- large-values: spec/data-model.md §5 a set or map with two elements or keys equal by link content hash is rejected; spec/crdt.md §5.5, §5.6 of equal links a read shows the lowest live element's or entry's (dot order).
- server: spec/wire.md §11.2 Register: a server MAY answer a genesis step for a new label with Error 12 at its storage cap (node-wide label/byte caps; `LabelStore::admit_label`).
- schema: spec/data-model.md §9: `creation`'s exclusive fields 0/1 type `/created` by spec/wire.md §3, not by the missing-field rule (the type system cannot say "exactly one of").
- TLC findings (models/tla; rationale in notes/sync.md, notes/permissions.md, notes/crypto.md, notes/ephemeral.md):
  - S1: spec/commits.md §5: a commit carrying a purge request MUST NOT carry `expires` and its blobs are kept at least until `ts + MEMBERSHIP_KEEP` whatever its deltas' bounds (spec/wire.md §4 bad-input list extended). Affects commit (header validation), node-core (retention), api (a purge and its resets form a commit of their own).
  - S2, S10: spec/commits.md §5 compaction snapshots take the schema's default bounds, never a commit's; spec/sync.md §7 a right holder that must delete a live body and finds no carrier uploads a covering snapshot first; the "member MUST always serve current state" sentence replaced by "live state is never lost" (node state, spec/crdt.md §4.6, or a label entry).
  - S3: spec/sync.md §6 must-not-hold wins every overlap. S4: literal reading kept (no edit). S5: spec/commits.md §5 and spec/sync.md §7 a live body leaves a label only while a covering snapshot, a superset blob of the commit or an identical body stays under it (duplicates need no wait). S6: a reader relays stamped must-hold entries the label lacks. S7: a compactor drops a may-hold body once per (commit, delta set). S8: a purged body is kept as a rewrite, header-only when nothing remains, by whoever drops it; spec/sync.md §3 "an expired class is deleted rather than rewritten". S9: a body holding no delta is covered; a snapshot from a node's whole state covers every body it applied.
  - R1: spec/permissions.md §3 and spec/commits.md §2: a removal or demotion and the rotation of the target's roles it requires are one membership commit; re-seal decisions after a full sync pass, never for a member whose `until` is within `MAX_DRIFT`, boxes to the member's newest keyset the node holds; re-seal delivered by inbox only (label delivery dropped). spec/crypto.md §4: boxing an epoch's secret to a member is encrypting under it (R6). spec/sync.md §3 inbox blob = the parts about G; spec/permissions.md §4 certificate edge writes projected to their edge deltas.
  - R2: spec/permissions.md §4 stranded heartbeat also on a refused claim, wrapped under the newest secret held (spec/crypto.md §5); spec/sync.md §5 such a member is reached by re-seal. spec/crypto.md §3 deposit-seed refresh SHOULD → MAY (it refused stranded heartbeats).
  - R3: spec/crypto.md §4 a grant or re-seal re-writes the history boxes of the epochs it boxes. R4: spec/sync.md §5 re-registration compares (n, nonce) per role against a head epoch the admin holds; otherwise it walks first. R5: spec/crypto.md §5 wrap under the newest current epoch held; a node with no current secret places only its stranded heartbeat. R7: spec/sync.md §2 claim set is as of registration; a re-sealed member opens by sync key.
- crdt-core: spec/crdt.md §4.2, §5.1, §7, §3.2/§3.3 rule 4: nested multi-encoding positions under a parent reset joined order-dependently in the model (members carrying the position reset and "encodings seen are grow-only"). Now: slot members are pruned like any fragment and do not copy the position reset; a member below the register's embedding is dropped; a register's reset below its write goes; a nested `R` below `E_parent` goes. Model updated to match; `model_order_independent_spec_7` checks it.
- crdt-seq: spec/crdt.md §4.5: an element created and removed in one commit is omitted only once no other write of the commit anchors at it (repeatedly); re-anchoring its dependants to its anchor, as before, reordered them among that anchor's children, so a batch read differently from the same ops one by one (found by `text_batch_is_net_effect_spec_4_5`).
- crdt-seq (decided in review): spec/crdt.md §3.3 rule 7, spec/wire.md §2: outside snapshots a bare-anchor run is rejected; a writer or import delta carries at most `MAX_DELTA_BARE` = 2^18 elements in runs without `Content`, pages included (longer deletes split across commits); a writer's `FlagW` stamp is the delta stamp.
- crdt-core: spec/crdt.md §5.6, §9: a map put or diff into a key with several live entries diffs against the key's read (join of its live entries), not the lowest entry alone; otherwise `read(join(S, diff(S, v))) == v` failed for concurrent puts. Model updated.
- label: spec/wire.md §13: a claim set with its entry boxes is at most `MAX_MESSAGE` − 64 KiB, so a step and its set fit one Register message.
- crdt-core review: spec/crdt.md §2.2: a `Derived(d)` dot orders as `(d.source, d.ctr, i)`, right after the write it embeds (it sorted above every source, so a reset at the same `ts` above the register write kept the embedded characters in some delivery orders). §4.8 names the implied register reset. Model updated (`embedded_chars_order_right_after_their_write`).
- proto: spec/wire.md §11.2 Sync: a replay without a cursor pages in blob ID order with a replay cursor `[replay_id, pos]` and ends with the log cursor taken at its start (paging by log position failed on a compacted log: the next page's cursor was below the horizon).
- proto: spec/wire.md §11.2 Opened's `entry_box` travels as the canonical bytes of the box value in a byte string, like steps and claim sets (the layout did not say).
- commit: spec/commits.md §5: compaction snapshots of membership-class aspects and `/created` keep the fixed retention (the text read as if every snapshot delta were `writer`); `/created`'s "forever" is `abs` = forever on the wire. spec/wire.md §4: a header token no aspect lists is bad input.
- keys: spec/crypto.md §3 a key actor's role secrets sit at the fixed epoch (0, 16 zero bytes) (derived things and symmetric boxes need an epoch); §4 a rotation's key-actor box also carries the newest secret of the roles below its key that it does not rotate (removing the old box stranded them); spec/permissions.md §3 the cascade rotates on each thing only the roles A holds there among those M could open through A (per-role KEM keys).
- TLC round 2 (design escalation; rationale in notes/permissions.md, notes/crypto.md, notes/sync.md, notes/ephemeral.md; model changes in plans/tla-models.md Progress; code obligations in issues/keys-established-epochs.md):
  - R9, residue 1 (MC_reorder, MC_fork_reorder): spec/crypto.md §4 **established epochs**: own, fixed/derived, applied rotation commit with its whole superseded chain applied, or keyed by a held `/secrets` compaction snapshot; current = established not superseded by an established rotation; a node encrypts under, boxes (history boxes, grants, re-seals) and rotates over established epochs only, other secrets read only; `/secrets` compacted only from a fully established state. Opening a label is not encrypting under (a re-sealed member needs the sync key to fetch the commit). spec/permissions.md §3 re-seal only at chain-established current epochs (snapshot-established: no re-seal, MAY rotate), decided at the end of a complete pass (R8: the log of every server and peer it syncs the actor's labels with read to its end). spec/sync.md §5 the registrar uploads the actor's membership commits the server lacks (the rotation chain) under the head's keys, then registers, then the rest (was: register before any upload). spec/permissions.md §4, spec/crypto.md §5 the stranded heartbeat is placed after a complete pass at that server and wrapped under the newest established secret. Affects keys (`usable` → established), node-core (establishment fixpoint, persisted), node-sync (pass-complete event, upload order), membership-flows (re-seal gate).
  - S11, S13: spec/commits.md §5 a writer holding no covering snapshot writes one before dropping a body with live writes (local drop at a keep-at-most bound, offline included); a timed delete of a body with live writes goes with the snapshot like at most 0. S12: spec/sync.md §7 an identical body carries only the one with the higher blob ID; of covered-equal snapshots the higher commit ID goes. S14: spec/commits.md §5 nodes keep the headers of applied commits; a header-only rewrite is covered (may-hold). S15: accepted (offline copy; notes/sync.md). Purge commits' `MEMBERSHIP_KEEP` overrides keep-at-most too (wording).
- keys review: spec/crypto.md §4 the covers rule for a departure inside a member is recursive (M's box names M's newest keyset epoch and that epoch covers the departure); spec/permissions.md §3 a node rotating for a departure inside M rotates the intermediates top-down where it may, else does not encrypt under the epoch (stranded until the intermediate rotates). Scenario: device D removed from person P, P member of team T, T member of doc U: U's writers kept encrypting under U's old epoch because T's box at U still named T's newest keyset. Also spec/crypto.md §4: a rotation that removes a key actor's box and writes it no role writes it one box with every role it holds; a grant to a key actor carries each role's newest current epoch; carried secrets are encrypting under their epochs (an uncovered carried role is rotated too). §5: the rotation commit wraps under the newest superseded read epoch whose secret the rotator holds. spec/sync.md §5 "greater (n, nonce)" → "newer". spec/permissions.md §3 cascade wording ("the roles M left").

## Owner-calls pending
- issues/token-admin-secret.md (a non-admin writer cannot derive the level-1 delete token; provisional: omit it; recommended accept for MVP).
- issues/header-list-commitments.md: header-list chunks of commits with more than 16 token secrets carry only author-chain commitments (provisional).
- issues/reseal-triggers.md: members no automatic re-seal trigger reaches when their deposits are refused (R2; the wrongful-re-seal residues were closed in TLC round 2); recommended: accept for the MVP, mechanisms listed.
