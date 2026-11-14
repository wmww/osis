# Sync boundary: what the engine keeps, replaces and deletes for the new sync
> Summary: Phase 2 of issues/sync-rewrite.md, inventory half: every pub item of the engine (and of label, store, proto, osis) that only the code Phase 3 deletes calls, and the engine state that serves only old sync, each marked delete / keep / replace / unsure with its reason, grouped so Fathom can see what to steer clear of. The interface half (what the new sync calls, what the engine emits) is written from the new sync spec.

Judged against the final design (spec/sync.md and its area files as Phase 1 writes them; notes/sync-rewrite-inputs.md; notes/cannot-read-audit.md): a node keeping S unread holds a sync record (tid, sync IDs, sync secrets by epoch) and needs nothing from the engine about what S carries; one home sync ID per actor, recorded in `sync.0`; derived values are `osis_base::memo` values over the engine's stamps, with effects run on change (issues/derived-state-recomputed.md steps 3 and 7), never hand-keyed caches, counters or take-since-last-call queues.

Marks: **delete** (only old sync uses it, the new design needs nothing like it); **keep** (the new sync or another caller needs it as it is, possibly renamed for the words of issues/sync-rewrite.md); **replace** (the new design needs something like it, said what); **unsure** (question in Unsure). Names are as of fd712b177; spec file names (spec/sync-ids.md and the other area files) are those of the sync-spec branch.

## For Fathom: what to steer clear of
Branches on keys, rotation, perm and engine judgement should not build on, extend or rename these until Phase 3 lands; they change or go there.
- **Delete:** `Core::generation`, `role_generation`, `memory_generation` and `Core::role_changed`; `Core::changed` with `Changed`, `Wakes` and `Engine::take_changed`; `Core::made_labels`; `Engine::recheck`; the kept-unread branches inside `rotation::lost::may_hold`/`may_take` (the `Role::Sync` arm), `flows::retake`'s sync boxes, `drop_actors`' sync-secret keep, `labeling::certs::boxed_by`'s sync invariant, `labeling::actors::inbox_actors`' count of a thing held for sync only, `rotation::add_history` with `role_now` = Sync, `retention::destroy::hold_secrets` counting a sync secret; `GroupLabel::hosts`.
- **Replace:** the sync-ID layer (`labeling::actors::{labels_of, labels_read, group_labels, labeled, labeled_groups, published_under}`, `GroupLabel`, `Indexes::labeled`, `Core::labels`, `Core::published`: becomes `sync.0` and one home sync ID per actor); `Indexes::syncing` and `Engine::set_syncing` (becomes the synced group S); the hooks `SyncRecords` (with `Core::sync_records`, `Engine::set_sync_records`) and `SyncState::complete_pass`; the take-queues `take_fallen`, `take_fell`, `take_pended`, `take_redeliver`, `take_freed_new`, `take_destroyed_secrets_due`, `take_memory_drops` and their sets; destruction emptying (`emptying`, `emptying_things`, `labels_emptied`, `drop_destroyed_secrets`, `commits_keyed_by`, `Indexes::destroyed_labels`, `Indexes::destroyed_secrets`); `flows::edges::inbox_chain` and `deliver_parts`' chain to holders below read; `learn_secret`'s sync secret; `labeling::converge` (`Facts`, `classify`, `may_delete`); `purge_resnapshots`' caller (the fn stays); the raw state access listed under B below.
- **Free to change:** everything marked keep, including all of rotation (`ensure_rotated`, `reseal_due`, `blocked_roles_of`, departures), lost access (`judge_lost`, `forget_lost`, `lost_leaving`), validity, retention bounds and certificates. Only their call sites in `core/node/src/sync` go.

## How it was found
Every `pub`, `pub(crate)` and `pub(super)` fn, const and field of core/engine, core/label, core/store, core/proto and core/osis got `#[deprecated]` (3713 items, a throwaway probe); `cargo clippy --all-targets --message-format=json` gave every use site; an item counts as only-old-sync when every use is in `core/node/src/sync`, `core/host`, `core/node/tests/it`, `core/proto/src/{session,store,window}.rs`, `core/test/sim/src/{net,scenarios.rs,world.rs}`, or inside the body of another such item (to a fixpoint). Result: 575 items (engine 451: 284 methods, 145 fields, 13 fns, 8 associated fns, 1 const; label 24; store 22; proto 76; osis 2), plus about 180 store and proto items used only by deleted code and their own crate's tests.

The node wraps the engine (`SyncEngine` owns the `Engine`; osis reaches the engine only through it), so "only old sync calls it" covers much of the engine's whole API: opening, writing, ingesting, the clock. Those are marked keep in group A. The named start points that have no item of that name: `keeper_due` (nearest: `lost_leaving`, `would_forget`, both keep) and `destroyed_labeled` (it is `Indexes::destroyed_labels`, replace).

## Engine functions
### A. The engine's API the node needs whatever sync is: keep
| items | mark | reason |
|---|---|---|
| `Engine::open`, `create`, `run`, `reload`, `now`, `tid`, `account_tid`, `identity`, `first_admin`, `record_chain`, `store_writes`, `subscribe_durable`, `blobs`, `clock` | keep | opening, transactions, identity: any node |
| `Identity::keys`, `Identity::record`, `Mutation::new`, `op`, `replace`, `write::commit`, `write::role_of` | keep | writes the node makes (peer records, links) |
| `events::Events::diagnostic`, `flush`; `Diagnostic` fields `commit`, `detail`, `kind`, `peer`, `tids`; `DisputeInfo` fields, `Side::chosen`, `trust` | keep | events and API types, read through the node |
| `read::epochs`, `get_typed`, `references_to`, `role_on` | keep | plain reads |
| `records::Rd`, `records::Wr` (16 methods) | keep | the store record codec; the new sync's records use it or it goes in Phase 3 if none does |
| `Engine::examined` | keep | scale-test counter |

### B. Raw state access: replace by the boundary's queries
The new sync asks narrow questions (per sync ID: held commits and their bodies, judgement, keys); these give it the whole engine. The fields stay, the `pub` access goes.
| items | mark | reason |
|---|---|---|
| `Engine::core`, `Core::ix`, `Tx::txn`, `Tx::scan`, `Tx::get_commit`, `Tx::in_class` | replace | whole-engine handles; the boundary names what sync reads |
| `Indexes::by_aspect`, `commits`, `held`, `own_keys`, `pending`, `secrets`, `snapshots`, `destroyed_secrets` (read side) | replace | raw indexes; each use becomes a boundary query |
| `JMap::get`, `contains_key`, `JSet::contains`, `JSetMap::get` | replace | journal internals exposed only for the above |
| `Meta::{header, origin, received, valid, view, body_gone, dropped, missing, missing_as}`, `View::{actor, aspects, author, kind, memory, purges, ts}`, `AspectView::tid`, `Trees::{blobs, missing}`, `refs::Reference::{ak, source}`, `Dropped::why` | replace | commit metadata read field by field; the boundary returns what a judgement needs |
| `Core::{account, accounts, id, key_actors, timelines, time, horizon, events, aspects_of, durable_on, held_on, cover_judged_on, destroyed, exists}`, `Core::created`, `held::Timelines::get` | replace | same; `horizon` and `time` become the memo clock the boundary's memos read |
| `held::Held::{below, holders_of, named_holders, named_on, reach, upstream}` | keep | pure perm queries J and the open rule need |

### C. Change tracking for old sync
| items | mark | reason |
|---|---|---|
| `Core::generation`, `role_generation`, `memory_generation`, `Core::role_changed` | delete | hand-keyed counters; memos compare stamps (derived-state step 3's done-when) |
| `Core::changed`, `Changed::{commits, aspects, undropped, edges, wakes, is_empty}`, `Wakes::{records, moved, reread, woken, reopen_awaits}`, `Engine::take_changed` | delete | a change log for old sync's work sets; the new sync's values are memos over the stamps and its effects run when a value moves |
| `Core::made_labels` | delete | old sync learning new labels; a new sync ID is a `sync.0` change a memo sees |
| `Engine::recheck` | delete | polices the hand caches; goes with them (derived-state step 3) |
| `Engine::take_fallen`, `take_fell`, `take_pended`, `take_redeliver`, `name_redeliver`, `redeliver_named`, `take_freed_new`, `take_destroyed_secrets_due`, `take_memory_drops`, `MemoryDrop::by` | replace | take-since-last-call queues; each rule stays (snapshot turning invalid, logged again once after a fall, pending sweep, junk copy re-fetch, freed blobs, destroyed secrets, memory drops), each becomes an event the engine emits or a memo value |
| `Engine::set_sync_records` | replace | `SyncRecords` hook; see E |

### D. Sync IDs: replace
| items | mark | reason |
|---|---|---|
| `labeling::actors::labels_of`, `labels_read`, `group_labels`, `labeled`, `labeled_groups`, `published_under` | replace | label per group from `label.0`; the new design has one home sync ID per actor in `sync.0` (spec/sync-ids.md) |
| `GroupLabel::{id, steps, tips}` | replace | the sync ID with its path; same content under the new name |
| `GroupLabel::hosts` | delete | addresses in group data; readers dial what they know, never from group data |
| `labeling::HeadKeys::{delete, deposit, epochs, is_writer, sync, sync_established, write}`, `labeling::blobs::head_keys`, `deposit_seed` | keep | a head's keys; same rule per sync ID |
| `flows::labels::issue_step`, `drop_old_claims` | keep | steps and claim sets (area 2), renamed |
| `apply::set_syncing` | replace | the node's own list of synced groups; the sync set is the synced group S's closure (spec/sync-set.md) |
| `apply::hint_actors`, `apply::keys::inbox_named` | unsure | hint sync IDs (U1) |

### E. Kept-unread and inbox hooks
| items | mark | reason |
|---|---|---|
| `labeling::certs::boxed_by` | replace | keep the read rule (follow a payload's sync ID only for a thing the commit gave a read secret of); drop its sync invariant |
| `apply::keys::learn_secret` | replace | keep for read secrets from an entry box (links); a sync secret goes to the sync record, not engine state |
| `flows::edges::inbox_chain`, `deliver_parts` | replace | the chain and `keys.0` go only to readers; a sync grant carries its box and sync IDs (issues/stranded-holder-unread.md) |
| `labeling::actors::inbox`, `inbox_actors` | keep / replace | `inbox` keep; `inbox_actors` replace: readers' actors only (audit row Inbox actors) |
| `Engine::note_delete_hints`, `own_delete_keys` | keep | delete keys an inbox payload names (spec/wire.md §9), for holders that delete |
| `flows::{inbox_kem, inbox_of_actor}`, `Engine::account_kems` | keep | sealing and opening inbox blobs |
| `SyncState::complete_pass` (via `reseal_due`, `signing_due`) | replace | "a complete pass" becomes status per sync ID: every source's stream read to its end (area 7) |

### F. Judgement per sync ID for readers
| items | mark | reason |
|---|---|---|
| `labeling::actors::{closure, group_actor, may_read, reader_of, secret_actor}`, `engine::groups::enclosing` | keep | closure and entitlement: what S carries |
| `engine::groups::closure_whole` | keep | the header-only `group.0` wait is still an area 4 rule (inputs note) |
| `labeling::blobs::{body, body_ctx, body_carried, body_plaintext, commit_bodies_under, label_bodies_meta, readable_parts, reads_in, carries_secrets, copy_stale, await_reading}`, `Body` fields, `BodyCtx` fields | keep | what S carries per commit (Carry, spec/sync §3); renamed; `label_bodies_meta` is already a memo |
| `labeling::blobs::{seal, seal_to, open_commit, read_secrets, wrap_secret}`, `Sealed` and `OpenedBlob` fields, `fetch_order` | keep | the blob format (label crate's crypto, kept) |
| `labeling::blobs::{delete_secrets_of, delete_secrets_by_group}`, `labeling::delete_item`, `delete_item_by_level` | keep | delete keys and Delete items |
| `labeling::converge::{Facts fields, classify, may_delete}` | replace | the must-hold / may-hold / must-not-hold rule set, rewritten from spec/sync-judgement.md as one memo per (sync ID, commit) |
| `labeling::certs::{certificates, author_chain, removal_certificates, revoke_certificates, minting_evidence, mintings_of, witness, header_body, part_body, linked_blobs, holders_named, current_keys, destroyed_needed, latest_by, aspect_commits, valid_parts, judged_valid}`, `Certs` fields and methods, `retention::Minting` fields | keep | certificate copies and minting evidence (spec/permissions.md §4, spec/commits.md §5); readers only |
| `labeling::judge::{judge, own_node, static_listed}`, `Judge::{known, of}`, `labeling::proofs::{account_key_open, account_prover}` | keep | J and account proofs: the open rule |
| `engine::large::{body_links, tree_missing, relink}`, `apply::reach::blob_wants`, `Wants::{missing, reached}` | keep | what to fetch; trees and chunks |

### G. Ingest, blobs and relay: keep
| items | mark | reason |
|---|---|---|
| `apply::{ingest, ingest_valid, ingest_with_lists, ingest_memory, apply_waiting_memory, learn_records, reexamine, pending, header, blob, commit_bytes, signed_at, parts_genuine}` | keep | taking commits and records in; any node that reads |
| `apply::{copy_awaits, records_awaited_by, destroyed_records_awaited, settled_slots, spent_copy}` | keep | unjudgeable and never-received rules (spec/commits.md §4-§5) |
| `apply::{forget_pending, no_entry_left, forget_awaiting, reading_sources}` | keep | the engine half of "the last entry carrying a commit left"; the new sync calls them from its store |
| `apply::memory::{holds_memory, memory_body_held, memory_bound, memory_charge, memory_pending}` | keep | ephemeral caps (spec/sync §9 caps) |
| `engine::blobs::{put_blobs, put_memory_blobs, has_blob, blobs_stored}`, `Tx::store_blobs`, `Cipher::{store, get, held, defer}` | keep | the engine's ciphertext door; the node's store per sync ID implements `osis_store::CipherHost` in place of the hub |
| `ephemeral::signal::{ingest_relay, take_signals}`, `EphCommit` fields | keep | relay-only commits (an emitted output) |
| `local_peer::package`, `header_list_blobs` | keep | a commit with its blobs, for relaying |

### H. Retention, destruction, forgetting
| items | mark | reason |
|---|---|---|
| `retention::bounds::{part_keeps, drop_from, body_not_dropped, coverers_of, delta_live, droppable_if_covered, may_last_on, own_kept_under, part_valueless, permanent, settle_kept}` | keep | keep bounds and covers (spec/commits.md §5), memos already |
| `Engine::{drop_body, own_covers, own_held_before, own_newly_covered, own_older, own_replace, part_held, kept_invalid, kept_purged, forgettable, all_forgettable, forget_commits}` | keep | covers and forgetting |
| `retention::{tick, timers_due, next_timer}`, `compact::compactions`, `snapshot::{snapshot, covered}`, `suspect::{suspects, state_digest}`, `purge::named_by_a_fallen_purge` | keep | engine retention; the driver's timer asks `next_timer` |
| `snapshot::purge_resnapshots` | keep | a re-snapshot every writer takes; only its caller (old sync's delete pass) goes: the engine runs it as an effect when `resnapshots_due` moves (replace, state below) |
| `Engine::left_at_hosts`, `Dropped::hosts_from` | keep | rules stay (no right deletes a part dropped while invalid; deletes at peers wait for `MAX_DRIFT`); renamed |
| `retention::freed::{judge_freed, judge_freed_page, freed_wants, freed_done, freed_delete_secrets, is_freed}`, `Freed` and `Judgment` fields | keep | freed links: deleting chunks through an entry the prefix commits to |
| `retention::destroy::{emptying, emptying_things, labels_emptied, drop_destroyed_secrets, commits_keyed_by}` | replace | destruction emptying stays (told, then emptied, sync IDs forgotten once heard out, secrets last); becomes a memo of the things to empty per sync ID with an effect, without the hand-kept due set |
| `retention::lifetimes::{judge_lifetimes, lifetimes_due}`, `Judged::request` | keep | lifetimes; "heard out" comes from status per sync ID |
| `retention::forget::Forgotten` fields | keep | what forgetting dropped; the new store drops its entries by it |
| `compact::compact_memory_now` | keep | test helper |

### I. Flows, rotation and lost access (Fathom's)
| items | mark | reason |
|---|---|---|
| `rotation::{ensure_rotated, rotated_already, blocked_roles_of, departures_placing, may_rotate, reseal_due, reshare, give_own_secrets_again, own_secrets_candidates, LOST_HEARD_WAIT_MS}`, `rotation::Leaving` and `Dropped` fields | keep | engine judgement; `reseal_due`'s `&dyn SyncState` argument changes (E) |
| `rotation::lost::{judge_lost, forget_lost, lost_due, next_lost_due, lost_leaving, would_forget, keys_write_unapplied}` | keep | lost access; "once its self-removals are placed" reads "logged" |
| `flows::{demote, removal_scope, finalize_link, joined_links_ended, links_due, next_link_expiry, may_remove, tied_unplaced, untie, signing_due, account_rotations, hold_lists, list_blob, rotation_lists}` | keep | flows and their triggers |
| `flows::{current_holders, is_key_actor, key_holders, role_now}`, `flows::account::{account_devices, counts_at_epoch, home_owner, is_account}` | keep | perm queries |
| `flows::Done::{commits, deliveries, drop_lost}`, `Demotion` fields, `HeldLink` fields | keep | a flow's result |
| `flows::Resend` fields | replace | the inbox re-send record behind `SyncRecords::note_unsent`; see E |

### J. Test helpers
| items | mark | reason |
|---|---|---|
| `testing::{rebuild_index, test_copy}`, `Engine::test_subscribe_with` | keep | copied worlds and index rebuilds for the Phase 4 harness |
| `local_peer::LocalPeer::{new, cached, peers}`, `Peer::{backend, clock, engine, root}` | unsure | U2 |

## Engine state that serves only old sync
| state | mark | reason |
|---|---|---|
| `Core::generation`, `role_generation`, `memory_generation` | delete | counters for old sync's caches |
| `Core::changed` (`Changed`, `Wakes`) | delete | change log |
| `Core::made_labels` | delete | queue of new labels |
| `Core::sync_records` and trait `SyncRecords` (`note_unsent`, `owe`, `forget`) | replace | what a flow owes must survive a crash in the flow's own transaction: the engine writes its outputs (inbox blobs, commits to log) as its own rows in that transaction and the new sync reads and clears them, or the new store's trait keeps this shape with no old-sync rows |
| trait `SyncState` | replace | status per sync ID (E) |
| `Core::redeliver`, `pended`, `fallen`, `fell`, `freed_new`, `destroyed_secrets_due`, `memory.dropped` (`MemorySync`) | replace | take-queues (C) |
| `Indexes::syncing` (`records::SYNCING`) | replace | the synced group S |
| `Indexes::labeled`, `Core::labels`, `Core::published` | replace | `sync.0` per actor |
| `Core::inbox_actors` memo | replace | readers' actors only |
| `Indexes::destroyed_labels` (`records::DESTROYED_LABELS`), `Indexes::destroyed_secrets` (`records::DESTROYED_SECRETS`) | replace | destruction emptying per sync ID (H) |
| `Core::resnapshots_due` | replace | a memo of the owed re-snapshots, its effect the re-snapshot; no sync caller |
| `Core::walks` (`apply::reach::Walks`) | replace | a cache kept for `blob_wants`: a memo over the pending set and held blobs |
| `Waits::untaken` sync entries | delete | sync boxes held back for `retake`; a sync secret goes to the sync record |
| `Core::memory_room`, `memory_waits`, `memory_tx`, `cover_candidates`, `missed`, `cut_subs`, `sourced_elsewhere`, `delete_hints`, `holder_keys`, `head_keys` and `holders_named` memos | keep | caps, covers, watch re-delivery, stranded reports, osis sources, inbox delete keys, perm |

## Other crates
| items | mark | reason |
|---|---|---|
| osis-label: `verify_stamp`, `verify_deposit`, `match_secret`, `open_inbox_item`, `entry_digest`, `wrap_order`, `tips`, `parse_record`, `Prefix::{agrees, for_groups, key_at}`, `Step::claims_hash`, `StepKeys::get`, `DeleteItem` fields and `verify`, `Class::in_memory`, `StrandedNotice` fields, `seal_stranded_notice` | keep | the crate's crypto parts (stamps, deposits, delete keys, steps), kept by the plan |
| osis-label: `host_prefix`, `prefix_bytes` | replace | the hub store's key layout; the new store per sync ID defines its own |
| osis-store: `nodelog` (`log_*`, `LogRead`, `LoggedEvent`) | keep | spec/sync.md (area 6) keeps one stream per peer over its node log; check its rules against spec/sync-streams.md |
| osis-store: `record` (`record_*`, `records_*`, `Record`, `Member`, `Filter`, `RECORD_BUDGET`) | unsure | U3 |
| osis-store: `changed` (`changed_at`, `changed_after`, `changed_note`, `changed_forget`, `changed_labels`) | replace | a hand-kept fingerprint per sync ID; a memo over the stamps of what decides a sync ID's credentials |
| osis-store: `Transaction::{put_blob, get_blob, read_blob, delete_blob, blob_len, suspend, table_len, random32}`, `Store::resume`, `prefix_end`, `Writes::{committed, failed}`, `test_copy*`, `Faults::test_copy` | keep | store primitives the new store per sync ID builds on |
| osis-proto: `session`, `store` (`LabelStore`, `MemoryLabelStore`, `HeadKeys`, `EntryMeta`), `window`, `Session::*`, `Relayed` fields, `session::{deposit, pulled, reply_bound, PUSH_POLL_MS}` | delete | the old session layer (Scope) |
| osis-proto: `msg` (constants, `Grant`, `SuspectEntry`, `is_reply_kind`, `stream_event_size`), `filter` (`encode_gcs`, `decode_gcs`, `pages`, `beacon_value`, `BEACON_P`, `Page`), `Code::*` | unsure | U4 |
| osis-proto: `prove` (`verified`, `ActorProof`, `MAX_PROOFS`, `MAX_RESUME_TAGS`), `frame`, `hello`, `relay` (`RelayGate`, `RelayLimits`) | keep | actor proofs for opens, framing, the relay (below sync) |
| osis: `internals::ManualNet::dbs`, `test_copy` | replace | the sim's world uses them; Phase 4's one harness decides its shape |

## Unsure
- **U1 Hint sync IDs** (`hint_actors`, `inbox_named`): spec/sync-ids.md §4 still has "sync ID hints" while a node holds no sync secret of g's own; whether a hint needs the engine to name its actors from unverified inbox commits, or the new sync takes hints from `sync.0` entries alone, is area 5's call.
- **U2 `LocalPeer`**: the engine's test peer, reached from outside only by node sync's test setup. Keep if the Phase 4 harness builds nodes on it, delete otherwise.
- **U3 per-peer records** (osis-store `record`): what a peer record holds (cursor, members of S, peer filter) depends on spec/sync-streams.md and spec/sync-opens.md; the rule "a record says only what need not be sent again" fits the new design, the rows may not.
- **U4 wire messages and the shared-set filter** (osis-proto `msg`, `filter`, `Code`): kept or dropped per message by the new spec/wire.md; `Code::NOT_ADMITTED` names a deprecated concept and is renamed or dropped either way.
