# Test code that can go: duplicates, vacuous tests, copied helpers
> Summary: Candidates for deletion or merging from a read of the tests under core/ (osis-sync's not read), each with what covers it, and helper families copied between test files. The gain is less code to compile, read and keep, not time (issues/test-time.md has the time).
> Priority: low
> Tags: tests

Every entry needs both tests read side by side before it goes. `tools/spec_map.py` counts the `§` citations above a test or in its file's `//!` header, so a merged test takes the deleted one's citation with it. Format: test | action | why safe | confidence.

## Vacuous or covered elsewhere
- engine `apply/tests_paged.rs first_diff_names_the_entry` | delete | tests a test helper's failure message | medium
- base `hash.rs blake3_known_answer` | delete | only the blake3 crate; vectors pin outputs | medium
- base `time.rs manual_clock` | delete | `ts_layout` keeps crdt §2.2 cited | medium
- base `chain.rs record_link_of_each_record` | delete | `each_end` and `depth_limit` walk every link kind | medium
- base `chunker.rs empty_and_tiny`, `page_closes_at_or_above_max` | delete | covered by `bounds`, `pages_match_rule` | medium
- base `tests/cbor.rs prefix`, `random_bytes` | delete | covered by `item_prefix_is_decoded_extent`, `mutation`, fuzz `cbor_decode` | medium
- base `tests/cbor.rs known_encodings` | shrink to cases `cbor/values.vec` lacks | medium
- crypto `rng.rs deterministic` | delete | only rand_chacha's seeding | medium (keep `unpad_rejections`: the only citer of wire §5 unpad)
- blob `auth.rs stamp_binds_wrap` | delete or one flip | `entry_signatures` covers the binding | medium
- keys `epoch.rs ordering_keys_match_folds` | delete or shrink | refactor scaffolding; the rule is in `current_and_newest` | medium
- osis `api.rs what_public_signatures_show_can_be_named_api_design` | drop its runtime field-read asserts, keep the compile-time guards | medium
- engine `rotation/tests_departs.rs`: its diagnostic baseline test | delete | low

## Merge
- osis `api.rs commit_place_of_any_time_api_design` + `commit_and_place_text_forms_api_design` | medium
- store `pager.rs row_padding_classes` into `row_lengths_show_only_the_class` (bring its independent oracle) | medium
- transport `p2p.rs peer_*_connects` | one table | medium
- transport `quic.rs` + `mem.rs`/`manage.rs` | one conformance suite, like store's `memory_backend_suite` | medium
- sim `peers.rs world_*` | one World wiring test | low-medium
- blob `step.rs claim_key_per_step` | one seed | low
- keys `props.rs departures_and_current_holders` | maybe delete: a keys-level copy of engine `rotation::tests_property`, its unique part the `snapshot_keyed` / `unvouched` check | low

## Regressions a property now covers
- crdt `tests_life.rs` `expiry_laws`, `unmerge` (+ `seq_` twins) | fold unique checks into `crdt_equals_model`, delete | low-medium
- held-model `spec_thing_history.rs` tests on test-only src (`Eager`, `Body`, `history`, `replaced_at` in `thing_history.rs`) | delete | the `ev_*` twins run the same properties on the real `evaluate` | medium-high
- osis `text.rs`: single-merge cases | delete | `text_edit_random_against_reference` checks them exactly | medium

## Helpers to add or unify
| helper | replaces | where |
|---|---|---|
| `Engine::hand_secrets` (`HandSecrets`, built) | remaining `osis_commit::Secrets` impls of their own | engine, bench, commit verify, vectors |
| `common::forge(...)` commit builder | ~17 hand-built `CommitBuilder` sites | engine `it` validity, parts, receive, flows |
| `recv_all(&n, t)`; `arrive(..)`; `assert_eq!(check(..), None)` | dozens of sites | perm scenarios/queries/content |
| crdt `testutil::{via_snapshot, joined, node}`; `Pager::run_until_loaded` | ~100 sites and loops | crdt test files |
| one `samples()` | 2 copies | schema `core_types.rs` vs vectors `subjects/schema.rs` |
| one forger of a commit "as received" with the thing's real delete keys and a path whose edges are held | made-up delete keys in about six helpers; hostile commits along paths nobody granted | engine and sync test helpers |
| one builder of crdt `Commits` tables | nested `l(vec![...])` literals in about a dozen crdt test files | crdt tests |
