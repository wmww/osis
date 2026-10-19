# MVP run progress
> Summary: Resumption point for the plans/mvp_meta.md run: current wave, per-plan state (not started / running / review / merged / blocked), open escalations, spec edits made during the run, pending owner-calls, and environment facts. Re-read this and `git log` before acting.

## Environment
- 4 cores, 30 GB RAM: run at most ~3 compiling agents at once; stagger compile-heavy spawns.
- Tooling confirmed: Rust stable 1.98, nightly (for cargo-fuzz), cargo-deny 0.20, cargo-fuzz 0.13, cargo-nextest 0.9, Java 21 (TLC).
- Integration branch: `main`. Sub-agent worktrees under `.worktrees/`.

## Current wave
Wave 1 (tla-models still running from wave 0).

## Plans
| plan | state | notes |
|---|---|---|
| pre-flight plan diff | merged at cb6f1b0 | |
| workspace | merged at 4b6ec14 | plan folded into notes/architecture.md |
| protocol-spec | merged (spec/wire.md), toplevel-reviewed | plan deleted; owner-call issues/header-list-commitments.md |
| tla-models | running (opus, worktree) | wave 0, ∥, low priority |
| core alignment to wire.md | merged | osis-core constants and layouts fixed |
| crypto | running (opus, worktree) | |
| crdt-core | running (opus, worktree) | returns after step 1 (skeleton) for merge, then continued by message |
| perm | running (opus, worktree) | |
| test-infra | running (opus, worktree) | |
| schema | not started | starts on crdt-core skeleton merge |
| store | not started | wave 1, after crypto AEAD+kdf |
| crdt-seq, commit, label, keys, proto | not started | wave 2 |
| node-core, server, transport, large-values | not started | wave 3 |
| sim | not started | phase A after node-core layout; B after node-sync; C wave 5 |
| node-sync, membership-flows, api (first half) | not started | wave 4 |
| apps-e2e, cli, p2p, api (second half) | not started | wave 5 |
| hardening-signoff | not started | wave 6 |

## Open escalations
None.

## Spec edits
- Toplevel review of wire.md: `keyset` carries the epoch's suite ID (spec/data-model.md §9); spec/sync.md §5 says how a member peer authenticates another member's node (its `/reach` dialable key).
- spec/sync.md §3: a projection class whose blob would exceed `MAX_BLOB` splits into several blobs, greedily in aspect-list order (pre-flight found no path under `MAX_BLOB` for a commit touching many aspects). spec/commits.md §1: one delta must fit a blob; the writer refuses the rare struct-of-many-large-registers shape (issues/struct-delta-size.md).

- protocol-spec (filling TBDs into spec/wire.md) also changed: tree-node link content hashes cover child hashes, not the subtree's bytes (spec/data-model.md §6, spec/crypto.md §6; O(change) edits); a recovery key's nonce derives from its seed like a link key's (spec/crypto.md §3); blob AEAD AD is the clear prefix and the inbox AD adds it (spec/crypto.md §5); the token, purge and origin lists go inline-or-link like the aspect list instead of a token cap (spec/commits.md §1); header-list chunk commitments capped (spec/crypto.md §7, owner-call); entry boxes live inside the claim set the step hashes (spec/sync.md §2); a link may carry the sharer node's dialable key and relays for first contact (spec/permissions.md §9).
- crdt-core: spec/crdt.md §3.3 rule 2: a commit-form delta's own source sorts below every other commit ID in element/entry/run arrays (sorting by its real ID was circular: the ID hashes the delta).
- crdt-core: spec/crdt.md §4.2, §5.1, §7, §3.2/§3.3 rule 4: nested multi-encoding positions under a parent reset joined order-dependently in the model (members carrying the position reset and "encodings seen are grow-only"). Now: slot members are pruned like any fragment and do not copy the position reset; a member below the register's embedding is dropped; a register's reset below its write goes; a nested `R` below `E_parent` goes. Model updated to match; `model_order_independent_spec_7` checks it.

## Owner-calls pending
- issues/header-list-commitments.md: header-list chunks of commits with more than 16 token secrets carry only author-chain commitments (provisional).
