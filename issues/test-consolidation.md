# Test code that can go: duplicates, vacuous tests, copied helpers
> Summary: A read of the tests under core/ (not run; osis-sync's came later): medium- and low-confidence candidates for deletion or merging, each with what covers it, and some forty helper families copied between test files. The gain is less code to compile, read and keep, not time (issues/tests-4x.md has the time). Lists per file below, each with why it is safe and how sure the reader was.
> Priority: low
> Tags: tests

How to use: every entry left needs both tests read side by side before it goes (line numbers drift: find tests by name). `tools/spec_map.py` counts the `§` citations in the comment above a test or in the file's `//!` header, so a merged test takes the deleted one's citation with it.

## Candidates
Format: `file:line test | action | why safe | confidence`.

### Category 1: useless or vacuous

**engine `it`**
- `parts.rs:554 history_plays_past_a_no_op_write` | delete | tests only the `play` harness of a deleted differential (a seed 9350074 prefix) | medium-high

**engine, perm**
- `apply/tests_paged.rs first_diff_names_the_entry` | delete | tests a test helper's failure message | medium
- perm `queries.rs:375-376` `PurgeBy::from_id` asserts | delete | a constant restated | low

**crdt**
- `stamp.rs:338 counter_range_spec_2_3` | delete | `rejects_own_counters_out_of_range_spec_2_3` and `run_past_counter_range_rejected_spec_2_3` cover the boundaries | medium

**base**
- `hash.rs blake3_known_answer` | delete | only the blake3 crate; vectors (`kdf_purposes`, `commit_headers`) pin outputs | medium
- `time.rs manual_clock` | delete | `ts_layout` keeps crdt §2.2 cited | medium
- `chain.rs record_link_of_each_record` | delete | `each_end` and `depth_limit` walk every link kind | medium
- `chunker.rs empty_and_tiny`, `page_closes_at_or_above_max` | delete | covered by `bounds`, `pages_match_rule` | medium
- `tests/cbor.rs prefix` | delete | covered by `item_prefix_is_decoded_extent`, `mutation` | medium
- `tests/cbor.rs random_bytes` | delete | covered by `mutation` and fuzz `cbor_decode` | medium
- `tests/cbor.rs known_encodings` | shrink to cases `cbor/values.vec` lacks | medium

**crypto**
- Keep `unpad_rejections`: it is the only citer of the "wire §5 (unpad)" anchor.
- `rng.rs deterministic` | delete | only rand_chacha's seeding | medium

**others**
- label `auth.rs stamp_binds_wrap` | delete or one flip | Ed25519/BLAKE3 behaviour; `entry_signatures` and bundle `rejections` cover the binding | medium
- keys `epoch.rs ordering_keys_match_folds` | delete or shrink | refactor scaffolding comparing against replaced folds; the rule is in `current_and_newest` | medium
- osis `api.rs:1833` | drop its runtime field-read asserts | keep the compile-time guards | medium

### Category 2: consolidation

**engine `it` `validity.rs`**
- `:335` | delete | covered by `:3225` | medium
- `:300` | delete | covered by `:3251`, `:227`, `:269`, `:746` | medium
- `:1719, :1756, :1934, :1961, :2021` (reader-snapshot `*_changes_nothing` group) | one table | first check that no case targets a pre-validity code path | medium

**engine `it` `flows.rs`**
- `:439` | merge into `:454` | same `lost_setup` world | medium-high
- `:2212` + `:2070` | table over `locked_out` 1/2 | medium

**engine `it`, near-duplicates (all confirmed)**
- `write.rs:591` + `:673` | one paged-text script | medium

**engine `it`, other files**
- `waits.rs:439` | fold into `:617` | medium
- `waits.rs:325` | delete | medium-low
- `waits.rs:293` + `parts::part_missing_pages_waits_alone` | table | medium
- `edits.rs:109` | delete | `:577` shuffles over 10 seeds | medium-low
- `edits.rs:494` | delete | low
- `listing.rs:422 purge_by_author_any_order` (18 s) | keep the by × who table, run named orders only | medium

**osis**
- `api.rs:1635` + `:1762`; `:1845` + `:1720` | merge each pair | medium

**engine**
- `apply/keys.rs:1196` | merge into `genuine_grant_applies_after_flood` | medium
- `apply/tests_addenda.rs:99` | merge into `:191` | move the "§5.2 (Addenda, rule 2)" anchor comment with it | medium-high
- `apply/tests_validity.rs:287` | merge into `:328` | medium-high
- `rotation/tests.rs:1223` | merge into `:1188` | medium
- `rotation/tests_departs.rs:164` | delete | a diagnostic baseline | low

**perm**
- `incremental.rs:280 created_late_every_order` | delete | `record_edge_cut_late_record_every_order` (:315) has the same structure in all 720 orders | medium-high

**crdt**
- crdt-model convergence twins | one proptest per type, the parameter picked by seed | medium

**held-model**
- `props.rs:201, :225, :280` | share one reference per seed | medium
- `spec_fetch.rs:171` | merge into the `settled_reads_like_creation_first` loop | low-medium

**leaf crates and sim**
- store `pager.rs row_padding_classes` | merge into `row_lengths_show_only_the_class` (bring its independent oracle) | medium
- transport `p2p.rs peer_*_connects` | one table | medium
- transport `quic.rs` + `mem.rs`/`manage.rs` | one shared conformance suite, like store's `memory_backend_suite` | medium
- sim `peers.rs world_*` (4 tests) | one World wiring test | low-medium
- label `step.rs claim_key_per_step` | one seed | low

### Category 3: cross-crate duplication
- keys `props.rs departures_and_current_holders` | maybe delete | a keys-level copy of engine `rotation::tests_property`; its unique part is the `snapshot_keyed` / `unvouched` check | low

Kept on purpose: perm scenarios (seed-named minimal reproducers; the properties don't reliably hit them), engine rotation tests (model-case and churn reproducers), `tests_paged` and `engine::pages` (store internals the upper layers cannot see).

### Category 4: code that could shrink
Helpers are listed in (c). Per-test items:
- engine `apply/keys.rs:714 spread`: quadratic; replace with `sync_all` or deliver only missing commits | medium
- engine `tests_addenda.rs:150` inlines `forge_addendum` | high

### Category 5: regressions a property now covers
- crdt `tests_seq_ops.rs` `:143, :161, :224, :261, :286, :363` (single-writer, batch, converge, undo text and list) | delete | covered by `fuzz_seq::random_scripts_replay_spec_5_7`; update notes/crdt.md's "Beside it" list | medium
- crdt `tests_seq.rs:296`, `:303 snapshot_*_edits_match_model` (10.7 s) | delete or make them the ignored `_large` size | the follow-count tests call the same `snapshot_then_edit` | medium
- crdt `tests_seq.rs:1227 part_judges_as_whole_of_histories` (13.4 s) | one type per case, or run it in every mode of `crdt_equals_model` and delete | medium
- crdt `tests_life.rs:59 expiry_laws`, `:65 unmerge` (+ `seq_` twins) | fold their unique checks into `crdt_equals_model`, then delete | low-medium
- crdt `tests_seq.rs:105`, `tests_wire.rs:34` (mutated deltas never panic) | delete once `tests_decoder::same_delta` also joins and reads what it accepts | medium
- crdt `tests_laws.rs:129 forged_edge_copy_cached_placement` (a pinned seed) | hand-written reproducer or delete | low-medium
- held-model `spec_thing_history.rs:161`, `:188` plus ~50 lines of test-only src (`Eager`, `Body`, `history`, `replaced_at`) | delete | the `ev_*` twins run the same properties on the real `evaluate` | medium-high
- osis `text.rs:230` | delete | `text_edit_random_against_reference` checks single-merge cases exactly | medium
- roles-model `single.rs` (14 tests, used by nothing outside the model, mostly rejected rule variants) | Tess's call: it is a design record | low

Width (tests-4x pattern 4), no coverage loss:
- `tests_ops decoded_bound_holds_random_values`: 300 → ~50 seeds | low
- crdt-model `props.rs:280–325`: one type per case | medium
- `large_text_batch_is_net_effect`: one seed | low

Width, open: crdt `tests_winners` (`seq_winners_from_scratch`, `winners_from_scratch`) run 8 and 2 variants per proptest case. One variant per case would cut 5.6 s to under 1 s.

## Helpers to add or unify

| helper | replaces | where |
|---|---|---|
| one `testing::ForgedSecrets(Vec<CreationRecord>)` | ~8 near-identical `osis_commit::Secrets` impls (dedup from records, fixed delete keys) | engine `it` `common::Keys`, `receive::Dedup`, `validity::Dedup`, `validity::Dedups`; engine `tests_paged::Forged`, `apply/keys.rs`, `apply/tests_account`, `rotation/tests_account`; also bench, commit verify, vectors |
| `common::forge(...)` commit builder | ~17 hand-built `CommitBuilder` sites | engine `it` validity 9, parts 6, receive 1, flows 1 |
| `recv_all(&n, t)`; `arrive(..)`; `assert_eq!(check(..), None)` | 27, ~16 and 23 sites | perm scenarios/queries/content; incremental |
| crdt `testutil::{via_snapshot, joined, node}`; `Pager::run_until_loaded` | ~13, 4 and ~100 sites; 9 loops | crdt test files |
| one `samples()` | 2 copies | schema `core_types.rs` vs vectors `subjects/schema.rs` |

## Not covered
- **Bodies only skimmed** (names and comments only): engine `it` order's scripted bodies, scale, finalize, sessions, crash; osis port, runtime, listing, watch, commits, ephemeral, tracking, undo; engine most rotation files, undo, retention/mod.rs, labeling; perm scale and robust bodies; held-model most `spec_*` bodies; keys `established`/`names`, store `nodelog`/`record`, roles-model addenda/epochs/forget/edges/trust bodies.
- **Not read**: osis-sync's tests (written after this read; issues/sync-test-cost.md).
- **Not done**: the ephemeral random harnesses; whether `judgment_vectors_spec_permissions_5_2`'s replay repeats `check()`; whether the crdt Slots mode reaches a deleted embedded character.
- **Doc follow-ups if the removals land**: notes/crdt.md "Beside it" list; notes/engine-validity-rebuild.md (names `unmerge_spec_4_6`).
