# MVP run progress
> Summary: Resumption point for the plans/mvp_meta.md run: current wave, per-plan state (not started / running / review / merged / blocked), open escalations, spec edits made during the run, pending owner-calls, and environment facts. Re-read this and `git log` before acting.

## Environment
- 4 cores, 30 GB RAM: run at most ~3 compiling agents at once; stagger compile-heavy spawns.
- Rust stable 1.98; nightly, cargo-deny, cargo-fuzz, cargo-nextest install started at pre-flight (see "Tooling" once confirmed). Java 21 present (TLC runs; tla2tools.jar must be fetched).
- Integration branch: `main`. Sub-agent worktrees under `.worktrees/`.

## Current wave
Pre-flight.

## Plans
| plan | state | notes |
|---|---|---|
| pre-flight plan diff | running | opus agent in worktree |
| workspace | not started | wave 0, serial |
| protocol-spec | not started | wave 0, ∥; toplevel reviews every layout |
| tla-models | not started | wave 0, ∥, low priority |
| crypto, crdt-core, schema, perm, test-infra | not started | wave 1 |
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
None.

## Owner-calls pending
None.
