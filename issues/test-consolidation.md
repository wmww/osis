# Test code that can go: duplicates, vacuous tests, copied helpers
> Summary: What is left of a read of the tests under core/ for duplicates and copied helpers: entries in code other jobs are changing (rotation, keys, accounts; osis-sync's opens, inbox, links and dial tests), the greenfield thing-history tests without an `evaluate` twin, and helper families to unify.
> Priority: low
> Tags: tests

Every entry needs both tests read side by side before it goes. `tools/spec_map.py` counts the `§` citations above a test or in its file's `//!` header, so a merged test takes the deleted one's citation with it. Format: test | action | why safe | confidence.

## Waiting on other work
- keys `epoch.rs ordering_keys_match_folds` | delete | a differential against the hand-written folds the ordering keys replaced; the rule is in `current_and_newest` | medium
- keys `props.rs departures_and_current_holders` | maybe delete: a keys-level copy of engine `rotation::tests_property`, its unique part the `snapshot_keyed` / `unvouched` check | low
- base `chain.rs record_link_of_each_record` | delete | `each_end` and `depth_limit` walk every link kind; the accounts work rewrote it for key minting | medium
- engine `rotation/tests_departs.rs`: its diagnostic baseline test | delete | low
- osis-sync, in areas the accounts pairing and proofs pieces rewrite (its tests ignored with an `accounts:` label are theirs to decide):
  - driver `a_dial_times_out_on_time_after_the_clock_{jumps_forward,goes_back}` | fold into `a_silent_dial_times_out_and_redials_spec_sync_opens_1` as a loop over no jump, forward, back | `dial_times_out_on_time` is that test's first half plus a skew | high
  - driver `a_redial_comes_on_time_after_the_clock_{jumps_forward,goes_back}` | fold into `a_failed_dial_waits_one_pause_spec_sync_opens_1` alike (`redials_on_time`) | high
  - driver `a_store_failure_restarts_in_place_once_per_stretch`: dead `let _ = &mut st;`; inbox `T::join`: dead `let _ = Moved::Joined(..)`, `T::close`: `if contains { remove }` is `remove` | high
  - inbox `genuine_deposit_promoted_beside_stamped_forgery`, `forger_variants_hold_one_slot_until_an_opener_promotes`, `one_stamped_copy_per_delta` | maybe one `adds_delta` table test (the second copy of part 0 asserted twice) | medium
  - helpers: inbox, a reconnect of `T` (`take`, `join(Store)`, `agree`, four sites); opens, a `Work` difference since a count (the five-field subtraction in `standing_moves_one_of`, `change_one_of`, `reconnect_with`) and "two readers sharing n sync IDs, all open" (the first two) | high

## Kept, for now
- held-model `spec_thing_history.rs`: `purged_content_never_shows` (+ `_random`), `a_carried_join_makes_older_settings_add_nothing`, `kept_while_live_while_a_replacement_would_be_kept`, `concurrent_admins_lose_no_floor` run on the greenfield functions with no `ev_` twin: they hold the `Rule` negative controls notes/engine-retention-history.md cites, the carried join, and concurrent admins not holding each other's settings. An `ev_` twin of each would let `Eager`, `history` and `Rule` go from `thing_history.rs`.

## Helpers to add or unify
| helper | replaces | where |
|---|---|---|
| `common::forge(...)` commit builder | ~17 hand-built `CommitBuilder` sites | engine `it` validity, parts, receive, flows |
| `recv_all(&n, t)`; `arrive(..)`; `assert_eq!(check(..), None)` | dozens of sites | perm scenarios/queries/content |
| one `samples()` | 2 copies, now differing (schema's has `dial`, `caps`, `clients`; the vectors' `name`, `body`, `tag`) | schema `tests/it/core_types.rs` vs vectors `subjects/schema.rs`: move the schema test's checks (`same_fields`, typed-key round trip) beside the vectors' generator over one union |
| one forger of a commit "as received" with the thing's real delete keys and a path whose edges are held | made-up delete keys in about six helpers; hostile commits along paths nobody granted | engine and sync test helpers |
| osis-sync streams `Pair` helpers: restart b and rejoin (restart, close, join each), release and retake of a side's record, count of Pulls joining S from the start | 8, 7 and 14 hand-written sites | sync `tests/it/streams.rs` |
| one builder of crdt `Commits` tables | nested `l(vec![...])` literals in about a dozen crdt test files | crdt tests |

`Engine::hand_secrets` is not for the remaining `osis_commit::Secrets` impls: they sit where no engine exists (commit's own unit tests, the vectors' fixed bytes, bench's engine-free byte count).
