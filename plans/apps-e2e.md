# Example apps and end-to-end tests
> Summary: Prove the stack with headless example apps: a notes app (two devices, sharing, undo, large body), the chat pattern of notes/chat.md (personas, join by link, removal with rotation, disappearing messages, signals), and a folder-with-rights pattern. End-to-end tests run in the simulator and over the real transport against a real server process on localhost, the latter driven through the CLI (plans/cli.md).
> Tags: api, tests

Crates: `examples/notes`, `examples/chat`, `examples/folder`. Depends on: osis (API), osis-server, osis-transport (quic feature), osis-sim, osis-cli (plans/cli.md) for the localhost e2e. Unblocks: hardening-signoff.
Reference: notes/chat.md, notes/permissions.md (Patterns), notes/api.md, plans/testing.md §8. Spec trumps this plan.

## Deliverables
- `examples/notes`: schema file + generated types (build.rs via osis-schema codegen); create, edit (text session), share a note with another person (edge on the thing), two devices of one person, undo, a large markdown body, offline edit then sync, revocation; headless driver functions plus an e2e test module.
- `examples/chat`: the structure of notes/chat.md (chat actor, personas, messages as owned things placed in persona groups, reactions map, read marker, typing signals, disappearing messages via expiry, hide set, join by link, participant removal with rotation and entry deletion, time-bucket history groups); e2e test for join/leave/removal costs (byte counts logged as tier-2 budget checks against notes/chat.md estimates).
- `examples/folder`: folder actor owning its things; moving a thing out as a copy; mirror-edges helper variant.
- E2E: in the simulator (deterministic) and over QUIC on localhost with `osis serve` and two stores driven by `osis` commands (one integration test, tier 2; plans/cli.md).

## Steps
- [ ] notes app + e2e in sim; feedback to plans/api.md (refactor API).
- [ ] chat app + e2e; budgets; feedback to flows if a pattern does not fit (issue if a spec change seems needed).
- [ ] folder app; localhost e2e over the real transport through the CLI (needs plans/cli.md).

## Done when
All three apps' e2e tests pass in sim and the localhost two-device, one-server session passes; notes/chat.md updated from "not reviewed" to what was built. Delete this plan.

## Progress
