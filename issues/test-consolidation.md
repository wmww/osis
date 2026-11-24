# Test code that can go: duplicates, vacuous tests, copied helpers
> Summary: What is left of a read of the tests under core/ for duplicates and copied helpers: entries in code other jobs are changing (rotation, keys), the greenfield thing-history tests without an `evaluate` twin, helper families to unify, and osis-sync's tests (not read: the sync rewrite is changing them).
> Priority: low
> Tags: tests

Every entry needs both tests read side by side before it goes. `tools/spec_map.py` counts the `§` citations above a test or in its file's `//!` header, so a merged test takes the deleted one's citation with it. Format: test | action | why safe | confidence.

## Waiting on other work
- keys `epoch.rs ordering_keys_match_folds` | delete | a differential against the hand-written folds the ordering keys replaced; the rule is in `current_and_newest` | medium
- keys `props.rs departures_and_current_holders` | maybe delete: a keys-level copy of engine `rotation::tests_property`, its unique part the `snapshot_keyed` / `unvouched` check | low
- engine `rotation/tests_departs.rs`: its diagnostic baseline test | delete | low
- osis-sync's tests: not read; read them once the sync rewrite has landed.

## Kept, for now
- held-model `spec_thing_history.rs`: `purged_content_never_shows` (+ `_random`), `a_carried_join_makes_older_settings_add_nothing`, `kept_while_live_while_a_replacement_would_be_kept`, `concurrent_admins_lose_no_floor` run on the greenfield functions with no `ev_` twin: they hold the `Rule` negative controls notes/engine-retention-history.md cites, the carried join, and concurrent admins not holding each other's settings. An `ev_` twin of each would let `Eager`, `history` and `Rule` go from `thing_history.rs`.

## Helpers to add or unify
| helper | replaces | where |
|---|---|---|
| `common::forge(...)` commit builder | ~17 hand-built `CommitBuilder` sites | engine `it` validity, parts, receive, flows |
| `recv_all(&n, t)`; `arrive(..)`; `assert_eq!(check(..), None)` | dozens of sites | perm scenarios/queries/content |
| one `samples()` | 2 copies, now differing (schema's has `dial`, `caps`, `clients`; the vectors' `name`, `body`, `tag`) | schema `tests/it/core_types.rs` vs vectors `subjects/schema.rs`: move the schema test's checks (`same_fields`, typed-key round trip) beside the vectors' generator over one union |
| one forger of a commit "as received" with the thing's real delete keys and a path whose edges are held | made-up delete keys in about six helpers; hostile commits along paths nobody granted | engine and sync test helpers |
| one builder of crdt `Commits` tables | nested `l(vec![...])` literals in about a dozen crdt test files | crdt tests |

`Engine::hand_secrets` is not for the remaining `osis_commit::Secrets` impls: they sit where no engine exists (commit's own unit tests, the vectors' fixed bytes, bench's engine-free byte count).
