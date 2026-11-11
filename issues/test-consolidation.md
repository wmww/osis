# Test code that can go: duplicates, vacuous tests, copied helpers
> Summary: A read of every test under core/ (not run): medium- and low-confidence candidates for deletion or merging, each with what covers it, and some forty helper families copied between test files. The gain is less code to compile, read and keep, not time (issues/tests-4x.md has the time). Lists per file below, each with why it is safe and how sure the reader was.
> Priority: low
> Tags: tests

How to use: every entry left needs both tests read side by side before it goes (line numbers drift: find tests by name). `tools/spec_map.py` counts the `§` citations in the comment above a test or in the file's `//!` header, so a merged test takes the deleted one's citation with it. Three citations are cut off from their tests today by a `/// A header blind` const between the comment and `#[test]`: proto `loopback::handshake_and_clock_offset`, host `hub::register_open_sync_download`, host `limits::stale_sync_key_gets_exactly_one_step`. Format of an entry: `file:line test | action | why safe | confidence`.

## Candidates
Format: `file:line test | action | why safe | confidence`.

### Category 1: useless or vacuous

**node**
- `keep.rs` explicit `check_index()` in `copy_survives_restart`: keep it; a reopen runs no `check_index` (probed), so it is the only oracle run after the first reopen
- `required.rs:374 required_after_reopen_spec_commits_5` | delete | `ix.required` is in `index_digest`, so `check_index` compares it in every required.rs test; its assert is near-vacuous | medium
- `required.rs:217` `fixed_retention` assert | drop the line | the header assert at :221 restates it | medium
- `growth.rs:67 replace_census_probe` | delete | ignored probe with no assert; `single_writer_replace_grows_nothing` checks the property | medium
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

**node `retention.rs`**
- `:155 purge_sets_any_order` | fold into `:204 purge_rights` (add the requester-side asserts), then delete | medium
- `:2785` | merge into `:41 purge_on_replace` | same world, same first two asserts | medium-high
- `:891` + `:911` | merge into one world | `undo_never_outlives_expiry_random` also covers the second | medium
- `:318` + `:357` | merge (one `unlisted` world, two orders) | medium
- `:625 snapshot_right_any_arrival_order` (14 s) | cut to the two reversed orders | loses three-way interleavings | low-medium

**node `validity.rs`**
- `:335` | delete | covered by `:3225` | medium
- `:300` | delete | covered by `:3251`, `:227`, `:269`, `:746` | medium
- `:1719, :1756, :1934, :1961, :2021` (reader-snapshot `*_changes_nothing` group) | one table | first check that no case targets a pre-validity code path | medium

**node `ephemeral.rs`**
- `:3331` + `:3365` | table over `hold_opened` | medium
- `:205` + `:234` | table | keep `:205`'s shape: it is a seed-203 reproducer | medium
- `:1186` + `:1224`; `:903` + `:938`; `:3211` + `:3219` | merge each pair | low-medium

**node `flows.rs`**
- `:439` | merge into `:454` | same `lost_setup` world | medium-high
- `:2212` + `:2070` | table over `locked_out` 1/2 | medium

**node `inbox_life.rs`**
- `:113` | merge into `:691` | same world and pairing | medium

**node `sync_more.rs`**
- `:212 reconciliation_fallback` | delete | `trimmed_log_reconcile_deletes_absent_entries` asserts a superset | medium
- `:1369` | move its exact checks into `scale.rs:597 role_change_judges_its_labels_only`, then delete | same world | medium-high

**node `keep.rs`**
- `:142 no_default_erases` | delete | covered by `a_later_default_touches_no_past_removal` (erase case) | medium-high

**node `stream.rs`**
- `stream_differential_no_write_dropped` + `_paged`: keep apart; each is over the per-test time limit, so one test would only make the longest test longer, for about six lines

**node `sync_review.rs`, `deletion.rs`**
- `deletion.rs:1425` | merge into `ending.rs:84` | low-medium

**node, from issues/tests-4x.md pattern 5 (all confirmed)**
- `write.rs:591` + `:673` | one paged-text script | medium

**node, other files**
- `waits.rs:439` | fold into `:617` | medium
- `waits.rs:325` | delete | medium-low
- `waits.rs:293` + `parts::part_missing_pages_waits_alone` | table | medium
- `edits.rs:109` | delete | `:577` shuffles over 10 seeds | medium-low
- `edits.rs:494` | delete | low
- `peers_review.rs:579` | delete | covered by `peers::reach_under_every_label_and_rotation` | medium
- `listing.rs:422 purge_by_author_any_order` (18 s) | keep the by × who table, run named orders only | medium

**osis**
- `sync.rs:1854` | delete | medium-low
- `sync.rs` `a_thing_in_a_group_shared_directly_syncs_under_both`'s client grant: keep; `a_refused_grant_makes_no_sync_id` checks no grant to a client
- `sharing.rs:1349` | delete | medium-high
- `sharing.rs:1522` | delete | medium
- `sharing.rs:89` | merge into `:1254` | medium
- `tied.rs:871` | merge into `:854` | medium
- `keep_clients.rs:~690 a_chat_by_record_keeps` | delete | its setup is `sim(Some(true))` | medium-high
- `notes.rs:69` | delete | medium
- `api.rs:1635` + `:1762`; `:1845` + `:1720` | merge each pair | medium
- `tags.rs:164`, `:202` (ignored, never run) | delete | covered by sharing/sync role tests | medium

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
- **host `hub.rs` / `limits.rs` vs proto `loopback`.** Seven host tests (`register_open_sync_download`, `deposits_and_budget`, `deletes_and_tombstones`, `subscriptions_and_relays`, `horizon_falls_back_to_reconciliation`, `claims_and_static_entries`, `stale_sync_key_gets_exactly_one_step`) run the same scripts as their loopback twins; only the store differs, and host `agrees_with_reference_and_replays` ties the two stores. Delete the host copies after moving their unique asserts (genesis delete key, deposit count, tombstone lifetime) into loopback. `claims_and_static_entries` is the only citer of the "sync §5 (claim set hash)" anchor, so move its refusal and citation first. Medium.
- keys `covers.rs grant_raced_by_rotation` | delete | node `flows::reseal_raced_grant` | medium
- keys `props.rs departures_and_current_holders` | maybe delete | a keys-level copy of engine `rotation::tests_property`; its unique part is the `snapshot_keyed` / `may_compact_secrets` check | low
- node `listing.rs:136 page_stops_at_its_byte_bound` | delete | covered by osis `listing::page_bound_counts_large_values` | medium-high
- node `receive.rs:147 drift_parks` | delete | sim `drift_parks_until_clock_catches_up` and engine `clock::hlc_rules` | medium
- node `encodings.rs:99 sequences_converge` | delete | `held_set_decides` and `crdt_equals_model` | medium
- node `encodings.rs:27 every_encoding_converges` | keep unless held-model is shown to reach enum and bounded counters | medium-low
- sim `no_server.rs:329` (row 15) | delete | covered by osis `sync::wait_synced_waits_on_a_group_with_nobody_connected`; update row 15 of issues/no-server-audit.md | medium
- node `retention.rs:1872` vs engine `retention/mod.rs:1182 body_live_follows_validity` | the same scenario at two layers; add `body_live` asserts to the node test and drop the engine one | low
- node `validity::carol_variant` first half duplicates engine `tests_addenda::unsynced_removal_witnessed_by_a_writer` | trim the node half, keep the engine one (the precise test) | medium

Kept on purpose: perm scenarios (seed-named minimal reproducers; the properties don't reliably hit them), engine rotation tests (model-case and churn reproducers), `tests_paged` and `engine::pages` (store internals the upper layers cannot see), and node `keep` vs osis `keep_clients` (the node tests pin plaintexts and dates the API doesn't show). osis tied grants, links and routing have no lower-layer tests, so there is nothing duplicated there.

### Category 4: code that could shrink
Helpers are listed in (c). Per-test items:
- engine `apply/keys.rs:714 spread`: quadratic; replace with `sync_all` or deliver only missing commits | medium
- engine `tests_addenda.rs:150` inlines `forge_addendum` | high
- osis `sharing.rs:627`, `:639`: must-fail `try_until(…, 200)` walks all 200 steps | high
- osis `notes.rs:148 large_body_streams` (23 s): shrink to just above `CHUNK_THRESHOLD` | low
- osis `sync.rs:823`: builds `text_pair` and uses one node; move to text.rs | high

### Category 5: regressions a property now covers
- node `order.rs:3478 held_model_agrees_on_purge_rights` | delete | `held_set_decides` runs held-model at quick and reaches writer and admin purges | medium
- node `order.rs:2849 purge_before_write_resnapshot_repairs` (27 s, a ~50-step seeded history) | shrink to a minimal reproducer, don't delete | low-medium
- node `stream.rs:976` (9.5 s), `:892` | delete only after `stream_run` counts that its paged join and crash-mid-fetch cases ran | low-medium
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

Width, not applied: crdt `tests_winners` (`seq_winners_from_scratch`, `winners_from_scratch`) run 8 and 2 variants per proptest case. One variant per case would cut 5.6 s to under 1 s, but the saved regression seeds (`proptest-regressions`) would then replay one variant each and may miss the one they were saved for: first turn each saved seed into a named case with its variant.

## Helpers to add or unify

| helper | replaces | where |
|---|---|---|
| one `testing::ForgedSecrets(Vec<CreationRecord>)` | ~8 near-identical `osis_commit::Secrets` impls (dedup from records, fixed delete keys) | node `common::Keys`, `receive::Dedup`, `validity::Dedup`, `validity::Dedups`; engine `tests_paged::Forged`, `apply/keys.rs`, `apply/tests_account`, `rotation/tests_account`; also bench, commit verify, sim adversary, vectors |
| `common::forge(...)` commit builder | ~17 hand-built `CommitBuilder` sites | validity 9, parts 6, receive 1, flows 1 |
| `Net::carry(n, done)` | ~125 two-line `carry_out` + `actions` sites | ~20 node files; private copies at deposit_queue.rs:136, sync_review.rs:861 |
| `Net::account(n, &[host])` | ~30 sites | 7 node files |
| `Net::publish_reach` | ~27 sites | local_serve 16, cert_judge 5; `peers::reach` and `peers_review::reach` are near copies |
| `Net::label_of` | 4 identical copies | ephemeral, metadata, stream, reconnect |
| `Net::blobs_of` | ~8 copies or variants | sync_review, sync_round2, deletion, pinned, tombstone, timed_dead, pass_marks, sync_more, until |
| `common::big_text()` | 7 copies of the 300k string | encodings, stream, hostile_host, local_serve, replaced_chunks, tombstone, sync_more |
| move `send`, `carry`, `tags`, `add_tag`, `big`, `remove` to node `common` | identical copies | flows vs validity, flows vs shred, flows vs keep; shred `peer`/`reopened` vs flows `forensic_*` |
| one `s`, `ak`, `set_edge`, `edge` | duplicates and differing signatures | `common` vs `net` in node; `ak` also in write, memory, scale; engine has 4 `edge`, 4 `ak` and 39 inline `ct::Edge{..}` |
| `pair_window()`, `compact(net, n)`, `put_expiring(..)`, `memory_group(n, seed)` | ~39, 14, ~23 and 5 sites | node ephemeral.rs |
| `fresh(lp, seed, pks)`, `commits_by(..)`, existing `of()` | 32, 11 and 12 sites | node validity.rs |
| parametrise `unlisted`; `thing_with(lp, &[(i, Role)])` | 5–6 rebuilt purge worlds; 83 `set_edge(peers[0]..)` | node retention.rs |
| drop the redundant `net.run()` after `advance()` | ~85 lines | tombstone 33, deletion 19, sync_more 17, sync_review 9, stream 5, required 2 |
| one `people(w, n)` | `sync::people`, `sharing::alice_bob`, `tied::setup` | osis; also use `scenario::introduce` for ~35 inline contact-card imports |
| `common::pair_node(w, db, seed)` | ~25 inline pairing sites + 3 local helpers | osis |
| delete `tied::skip`, `sharing::skip_sync`, `sync::skip`, `sync_basics::skip` | ~66 uses that all equal `SetRoleOpts::default()` | osis (`tied::skip`'s doc is also wrong) |
| osis `common::{item, group, x, s, plain}` | byte-identical copies | sync, sharing (`s` in 10 files) |
| one real-time `until` | 3 copies | osis keep_clients, sources, port |
| `recv_all(&n, t)`; `arrive(..)`; `assert_eq!(check(..), None)` | 27, ~16 and 23 sites | perm scenarios/queries/content; incremental |
| crdt `testutil::{via_snapshot, joined, node}`; `Pager::run_until_loaded` | ~13, 4 and ~100 sites; 9 loops | crdt test files |
| move `s32`, `events_of`, `statuses`, `added`, `sync`, `sent` into `osis_proto::examples`; a ClientSession Start+Hello helper | 2 copies each; ~12 sites | host common vs proto loopback; loopback, slow_link, hostile_peer |
| one `samples()` | 2 copies | schema `core_types.rs` vs vectors `subjects/schema.rs` |

## Not covered
- **Bodies only skimmed** (names and comments only):
  - node: flows 700–2036, tombstone, scale, the rest of required, inbox_life's hint and budget tests, order's scripted bodies, hostile_host, most of local_serve, connection_proofs, net_judgment, net_accounts, cert_judge, finalize, until, sessions, deposit_queue, deposits, inbox_retry, signals, pinned, nodelog, keys, pass_marks, metadata, revokes, labeling, negative, parts_relay, port_tiers, shared, crash.
  - Not read at all: node driver.rs, hub_loop.rs; memory.rs is all ignored by-hand RSS checks.
  - osis: sources, port_clients, port, runtime, listing, watch, commits, ephemeral, serving, tracking, undo, sync_basics.
  - engine: most rotation files, undo, retention/mod.rs, labeling.
  - perm: scale and robust bodies.
  - held-model: most `spec_*` bodies.
  - leaf crates: keys `established`/`names`, store `nodelog`/`record`, roles-model addenda/epochs/forget/edges/trust bodies, sim `scale`/`work_sets`.
- **Cross-layer comparisons not made:** osis ephemeral vs node ephemeral, watch/tracking vs engine, sync_basics vs node `sync*`, serving vs node `local_serve`, port_clients vs node `port_tiers`; engine retention/apply bodies vs node; the sim vs node tombstone, shred and required. More duplicates are likely there.
- **Not done:**
  - the ephemeral random harnesses (left to test-design step 9)
  - whether `judgment_vectors_spec_permissions_5_2`'s replay repeats `check()`
  - whether the crdt Slots mode reaches a deleted embedded character
- **Doc follow-ups if the removals land:**
  - notes/crdt.md "Beside it" list
  - notes/engine-validity.md (names `unmerge_spec_4_6`)
  - issues/no-server-audit.md row 15

