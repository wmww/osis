# Reference graph: the demolition inventory
> Summary: What step 2 of issues/reference-graph.md (Execution) deletes, found by reading and grep at 515e499c5: per old mechanism the source files, functions, spec sections, notes and public `osis` items; the tests that go and those that stay; the callers that must be stubbed to compile; the uses of "group"; baselines and line estimates; entanglements the plan does not name.
> Priority: normal
> Tags: engine, sync, tests

Base: 515e499c5. Line counts are `tools/loc.py` (non-blank, non-comment) unless marked `wc` (raw). "Est." means read and judged, not counted. A test count is `#[test]` functions whose body names a deleted item (a scan of every test body, list below); tests that use an old mechanism only through a helper are not in it.

## 1. Inventory per mechanism

### Thing lifetimes (retainers, release requests, `released.0`, judgment, `life` duty, held-model)
- `core/engine/src/retention/lifetimes.rs` whole (206): rows `lw/` `lh/` `lp/`, `status`, `queue`, `queue_with_listers`, `walk`, `unreachable_now`, `judge`, `Judged`, `Engine::{lifetimes_due, judge_lifetimes, release}`.
- `core/engine/src/retention/destroy.rs`: `release_state`, `released`, `forget_released` (wc 512-592) and the `queue_with_listers` call (est. 70 of 474). Callers of `queue_with_listers` in `apply/atomic.rs:524`, `retention/forget.rs:313`; `refs.rs:123,157` call `lifetimes::queue`.
- `core/engine/src/engine/write.rs`: `check_lifetimes` and its `kept`/`references` inputs (wc 1023-1040). `engine/mod.rs`: `lifetimes_rights` (4 sites).
- `core/engine/src/engine/refs.rs`: `RETAINERS`, `Reference::lists`, `listers`, the `RETAINERS` branches of `note`/`references` (est. 25).
- `core/commit/src/retention.rs` `RELEASED`, `release_expires`; `validate.rs:95-110` (release-request shape); `header.rs:201-220` `is_release` and its request items (est. 35 together).
- `core/sync/src/life.rs`: `Life::lifetimes`, `syncs`/`ids`/`heard`/`newly` state (est. 60 of 212). The rest of `Life` stays (below).
- `core/osis/src/write.rs`: `Write::release` (369), `AspectWrite::retaining` (781) and the modifier error path (est. 40); `core/osis/src/keys.rs:95-102` `core::RETAINERS`; the `lib.rs:226-235` doc example.
- `core/schema/src/core_types.rs` `RETAINERS`, `RELEASED`; `schema/core.osis` `retainers^.0`, `released.0`.
- `core/test/held-model/src/lifetimes.rs` whole (264) and `pub mod lifetimes` in its `lib.rs`.
- Spec: the lifetime rules of spec/commits.md (§5, L293-301, gone in the spec rewrite) and the release half of its Destruction (L271-292); spec/data-model.md §9 `released.0`, `retainers^.0` bullets; spec/requirements.md L123 (garbage collection).
- Notes: notes/lifetimes.md (wc 131), notes/engine-lifetimes.md (wc 51), notes/api.md Lifetimes (L137-145), rows in notes/growth.md, notes/engine-refs.md.

### Synced groups, default filing, shared here
- `core/engine/src/sync/set.rs`: `synced_group`, `sync_root`, `synced_closures`, `sync_roots`, `rooted`, `unshare_here`, `load_unshared`, `prune_unshared`, `Core::{account_shares, stays_local}`, `shares`, `kept_local`, `shared_here` (est. 150 of 393). `node_closure`, `sync_things`, `things_entered` stay as callers to stub (they walk the `Groups` index).
- `core/engine/src/flows/account.rs`: the synced group made at creation and pairing, `synced^.0` writes (L1137-1225, est. 50).
- `core/engine/src/sync/inbox.rs` `synced_roots` (counted under invitations).
- `core/osis/src/share.rs` `Osis::unsync` (702); `core/osis/src/syncing.rs` `GroupSync::leaving`, `Status::kept`.
- Default filing: no core mechanism. It is app code: `main_group` in `app/src/store.rs:43` (a subgroup of `Osis::home()`), `libs/chat/src/lib.rs:74` (`w.group(db.home())`), and the D-derived items of the `Groups` index (`DERIVED`, `key_home`, `rehome`: "carried for being made under an actor", plan Sync units).
- Schema: `SYNCED`, `synced^.0`. Spec: spec/sync-set.md §1 (L6-14), §2 (L15-28), shared here at L19; spec/data-model.md §9 `synced^.0`.

### The group as a sync unit (`group.0`, `groups.0`, `Groups`, `Write::group`, tied grants)
- `core/engine/src/engine/groups.rs` whole (799 + 190 test): `Def`, `ITEMS`, `SUBGROUPS`, `DERIVED`, `touched`, `refresh`, `load`, `Groups`, `Closure`, `closure`, `sync_closure`, `key_home`, `rehome`, cut and stranded-by-cut, `Engine::{groups_of, enclosing, listed_in, closure_whole, listing_groups, carried}`.
- `group.0` special cases: `apply/atomic.rs` (31 hits: `groups::touched`, `Touched::group`), `undo/mod.rs` (42 hits: delete removing memberships), `engine/read.rs:18-70` (`groups.0`, `tid.0` synthetic), `engine/write.rs:160` `require_synced`, `sync_ids/{actors,blobs,published}.rs`, `sync/{bodies,certified,listed}.rs`, `flows/links.rs` (a redeem files its target). Est. 250 beyond groups.rs.
- Tied grants: `core/engine/src/flows/tied.rs` whole (139); `sync/held.rs` `tie_wants`, `judge_ties`, `tied_wants`, `tie_scope`, `tie_passes_done` (est. 70); tie handling in `retention/pending.rs` (14 hits), `retention/mod.rs` (13), `apply/keys.rs` (14), `apply/mod.rs` (9), `sync/mod.rs` (10), `engine/index.rs` (5); `core/perm/src/types.rs` `Edge::tied`, `Tie`, `cache.rs` (est. 30); `core/sync/src/life.rs` `holders` untie half (est. 30). Est. 350 in all.
- osis: `Write::group`, `GroupWrite` (write.rs 323, 637-668), `Member` (share.rs 47), `GroupsOf`, `groups_of`, `members` (read.rs 96, 344, 479, 489), `Osis::add_with_grant` (share.rs 492), `internals::{GROUP_ITEMS, GROUP_SUBGROUPS}`, port method `GROUPS_OF` (port/mod.rs 31, codec, serve). Est. 250.
- Schema: `GROUP`, `Group`, `GROUPS`, `Tie`, the `tie` type and `edge.tied` in core.osis. Spec: spec/data-model.md §8 (L100-104), §9 `group.0` bullet; the tied grants of spec/permissions.md (§2, L76-81, gone in the spec rewrite); spec/requirements.md Terms (group), L132 (tied).
- Notes: notes/tags.md (rewrite: tags stay, built on `holds.0`), notes/data-model.md groups part, notes/engine-roles.md, notes/api.md, notes/client-port.md (30 uses of "group").

### Invitation machinery
- Inbox blob payload kinds, `core/blob/src/inbox.rs` (329 + 123 test): `InboxPayload` (a role commit, the grant copy), `BoxesPayload`, `BoxedThing`, `GrantSig`, `Inbox` enum, `seal_boxes_payload`, `open_inbox_item`. `StrandedNotice` is the third kind (section 6). Est. 230 goes.
- Engine: `core/engine/src/sync/inbox.rs` whole (460: `WAITING` `iw/`, `HINTS` `ih/`, `take_inbox_bytes`, `take_payload`, `accept_invite`, `invitations`, `accept_in`, `accept_redeemed`, `mark_acted`, `synced_roots`); `sync/deliveries.rs` whole (251: what is owed by inbox blob, `delivery_taken`); `sync/records.rs` `Offer`, `OFFERS` `io/`, `set_offer`, `expire_offers` (est. 100 of 271); grant copies in `sync_ids/certs.rs` (`inbox_actors_of`, `grant_copy`, `kept_grant_copy`, est. 70); inbox delivery owed in `flows/edges.rs` (est. 40); facade entries in `sync/mod.rs` (est. 80).
- Sync: `core/sync/src/inbox/deliveries.rs` whole (233); `inbox/held.rs` taking and stamping in place of inbox blobs (est. 200 of 353; deposit promotion stays); `inbox/offers.rs` `Target::Recipient` (est. 80 of 273); `inbox/mod.rs` wiring (est. 50). Invite requests (spec/sync-inbox.md L31) are the untaken blobs: they go with `held.rs`'s taking.
- osis: `Osis::{invitations, accept_invite}` (share.rs 908, 920), `Invitation` (174), `SyncScope::{Deliveries, Delivery}` (syncing.rs), port `INVITATIONS`, `ACCEPT_INVITE`. Est. 120.
- Schema `ACTED`, `acted^.0`. Spec: spec/sync-set.md §4 (L39-46); spec/sync-inbox.md §2 (L11-33), §5 (L63-69); spec/wire.md §9 (L206-232, the payload kinds); spec/crypto.md §5 inbox blobs (part of L237-259).
- Notes: notes/inbox.md (wc 51; Promotion and Clearing stay), notes/sync-inbox.md (wc 50, mostly), notes/sync-facade.md, notes/growth.md row.
- `kept^.0` (the plan removes it: tickets replace it): `sync/records.rs` `sync_kept`, `keep_in`, `unkeep_in`, `close_kept`, `sync_record*`, `record_borne` (est. 170); `core/sync/src/unread.rs` tied-to-thing rule (est. 60 of 144); schema `KEPT`, `Kept`; spec/sync.md §3 (L20-36), data-model §9 bullet; TLA `NetTrust`.

### `caps^.0`, `clients^.0` (move to the node root)
- Read: `core/engine/src/sync/set.rs:393-397` `caps` (facade `sync/mod.rs:456,1459`, consumed by `core/sync/src/store/mod.rs:588-593`); `core/osis/src/port/serve.rs:253-270` (client auth).
- Written: `core/osis/src/clients.rs` (`add_client`, `clients`, `remove_client`, `rotate_client_secret`, all on `self.node()`); `cli/src/cmd.rs:1330` (`clients` command); tests `core/engine/tests/it/facade.rs:103-112`, `core/osis/tests/it/port.rs:419`.
- Not logged today because no sync unit carries the node thing's aspects but `keys.0`, `node.0`, `reach.0` (certificate cards, `sync/facts.rs`, `sync_ids/certs.rs` `CARD`): inferred, not verified.

### The reference index's exclusions
- `core/engine/src/engine/refs.rs:29` `indexed`: excludes signals, `created.0` and role-class aspects; `RETAINERS` rows are kept but marked listers. The plan indexes all of these (est. 25 lines change).

### The tid value tag
- `core/base/src/format.rs:17` `TAG_TID = 1616`; `Value::Tid` in `value.rs`, `cbor.rs` (encode, size, decode); `core/test/vectors/cbor/values.vec`; crdt-model `value.rs`.
- Schema type `tid`: `core/schema/src/{types,parse,schema,typed,codegen}.rs` (`Type::Tid`); 16 `tid` uses in `schema/core.osis`, 5 in ui.osis, 2 contact.osis, 1 event.osis.
- Synthetic `tid.0`: `core_types::TID`, `engine/read.rs:18,68`, `osis/src/write.rs` (1), schema tests.
- `Value::Tid` sites: 320 (engine 154, osis 103, base 14, schema 9, crdt 9, sync 6, crdt-model 6, cli 9, other 10). It is also the wire encoding of every tid inside a value: creation records (`base/src/ids.rs:97-133`), `roles.0` keys, `box_key.holder`, `left_out`. Spec: spec/data-model.md §5 (tag 1616, 2 lines), spec/commits.md (1).

## 2. Tests
Per crate, tests naming a deleted item: 273 tests, about 7,500 lines (engine 111/3,286, osis 78/2,114, sync 50/1,361, app 7/174, blob 5/94, schema 3/77, kit 3/75, held-model 5/72, cli 3/49, chat 1/49, commit 1/32, others 6/118). By mechanism (a test may count twice): group 154/4,864, invitations 83/1,904, synced 49/1,218, kept 31/739, tied 15/505, lifetimes 20/419.

Whole files: `core/engine/tests/it/groups.rs` (74), the `groups.rs` test module (190), `core/osis/tests/it/lifetimes.rs` (126), `core/sync/tests/it/life.rs` (133) and `life.rs`'s test (11), `core/test/held-model/tests/it/spec_lifetimes.rs` (330), `core/blob/src/inbox.rs` tests (123).

Mixed files (name patterns; test names carry the spec section they check):
- Names ending `_spec_sync_set_1`, `_2`, `_4`, `_5`; `_spec_sync_inbox_2`, `_5`; `_spec_data_model_8`; `_spec_sync_3` where kept^.0 goes: 117 tests in all, mostly `core/engine/tests/it/facade.rs` (56 tests touch old items, 1,297 lines), `core/osis/tests/it/sync.rs` (20/568), `core/sync/tests/it/flows.rs` (16/596), `core/osis/tests/it/api.rs` (19/538: membership, first member, groups_of), `core/sync/tests/it/siblings.rs` (8/211), `core/osis/tests/it/port.rs` (8/196), `core/engine/tests/it/flows.rs` (10/211), `core/sync/tests/it/keep.rs` (3), `inbox.rs` (3: `inbox_blob_offered_*`, `writer_stamps_taken_inbox_blob_in_place_*`), `links.rs` (2), `unread.rs` (2), `destruction.rs` (2 `a_*released_*`).
- Tied: `a_dead_tie_*`, `a_tie_dead_*`, `an_ended_tied_grant_*` (facade, sync flows), `a_grant_with_a_membership_goes_with_it_spec_permissions_2` (osis sharing.rs).
- Helpers: `core/sync/tests/it/harness/history.rs` `accept`, `file`, `introduce` (wc 94-111, 297-331); `harness::step` calls `history::accept` every step, so the sync differential (`convergence.rs`, wc 225) and the sim set (`sims.rs`, wc 128) grant only through invitations: they go or are rewritten. `libs/kit/src/testing.rs:87,373`.
- `tied: None` in 136 `ct::Edge` literals (52 files): a field edit, not a deletion.
- Models: TLA `net/NetTrust.tla` + `MCTrust.tla` (wc 241, 9 cfgs `U*`) exists for kept^.0 accepts. `net/NetDestroy.tla` (wc 255, 16 cfgs `D*`) models emptying after a release request: its emptying rules also serve purge, so it is rewritten, not dropped. held-model `lifetimes` (above). No sim scenario exists only for these.

Clearly testing what stays (keep): `sync/tests/it/inbox.rs` deposit, register and clearing tests (14 of 17); `leave.rs` (`_spec_sync_set_3`: leaving, the release precursor); `stranded.rs`; `keep.rs` step and certificate tests (6 of 9); engine `destruction.rs` purge-destruction tests, `order.rs` `held_set_decides`, rotation `tests_*.rs`; held-model `spec_*` other than lifetimes; osis `references.rs`, `backlinks.rs` (the index; adjust for the exclusions); perm tests (only `tied: None` edits).

## 3. Blast radius: what must keep compiling, and what stops working
- **engine**: `Groups` is the sync closure. `sync/set.rs` `node_closure`/`rooted`, `sync/listed.rs`, `sync/bodies.rs`, `sync/certified.rs`, `sync_ids/{actors,blobs,published,certs}.rs`, `sync/own.rs`, `sync/held.rs`, `sync/dial.rs`, `apply/keys.rs` (`key_home`), `events/mod.rs`, `engine/{acting,listing,testing}.rs` call it (23 files besides groups.rs). Stub: an empty closure. Then nothing syncs; that is expected until lane (b).
- **sync**: `life.rs` keeps role duties, lost-access drop and the joiner's leave; `inbox/` keeps deposits, `register`, `stranded`, `suspect`, `links`; `store/mod.rs` keeps caps. The inbox facade calls (`deliveries`, `delivery_feed`, `inbox_of`, `take_inbox_bytes`) need removal at their call sites in `inbox/mod.rs`.
- **osis**: `share.rs`, `read.rs`, `write.rs`, `syncing.rs`, `port/{mod,codec,serve,client}.rs`. `Osis::home()` as D goes (the account root is no app's home).
- **perm**: `Edge::tied`, `Tie`. **commit**: release-request validation. **schema**: core types and core.osis.
- **kit** (`libs/kit/src/store.rs`, 23 sites; `facets/members.rs`, `views/mod.rs`, `testing.rs`), **app** (`app/src/store.rs`, `demo.rs`), **chat** (`libs/chat/src/lib.rs:74`), **CLI** (`cli/src/cmd.rs`: `Groups`, `Members`, `Invitations`, `Accept`, `Unsync`, `group add|rm`, `share` via `add_with_grant`, inspect `Group`; `cli/src/write.rs` `member`): each loses its tag, home and member reads and writes.
- **tools**: `tools/spec_map.py` rows for spec/permissions.md §2 (tied, inbox delivery) and spec/sync-inbox.md; `tools/dogfood-member.sh` (`invitations`, `accept`); the now-unused `inbox_blobs`, `inbox_blob_without_chain`.
- Public items apps call that disappear: `Write::group`, `GroupWrite::{add, remove}`, `Member::{Item, Subgroup}`, `Osis::{members, groups_of, add_with_grant, invitations, accept_invite, unsync}`, `ReadOnly::groups_of`, `GroupsOf`, `Invitation`, `Write::release`, `AspectWrite::retaining`, `core::RETAINERS`, `SyncScope::{Deliveries, Delivery}`, `GroupSync::leaving`, `Status::kept`, `internals::{GROUP_ITEMS, GROUP_SUBGROUPS}`, `Value::Tid`. None returns: what `groups_of` answered is a thing's backlinks (kind and AK), and a handle carries its tid (issues/reference-graph.md References).

## 4. Uses of "group"
Counts (`rg -o -i -w 'groups?'`): engine 1,109 (src 884, tests 225), osis 632, sync 133, blob 136, crdt 38, commit 33, base 31, perm 29, schema 23, held-model 20, tla 8, proto 7, sim 5, keys 4, roles-model 3, store 3, kit 96, chat 2, app 66, cli 123, tools 69, schema/ 37, spec 195, notes 516, issues 129, docs 41.

A sixth outcome exists: **other** (an unrelated sense that stays): blob/wire delete-key groups (`blob.rs`, `auth.rs`, spec/wire.md L160), engine page block-list groups (`pages.rs` `GROUP`), commit `prefix_groups`, the memo `Group` container, test actors called groups. Most of blob, crdt, commit, base and pages hits are this.

Sample of 30 (`random.seed(0)` over `rg -n` lines):
| use | outcome |
|---|---|
| engine `groups.rs:245` `group_ak`, `:532` "has a `group.0` state" | goes (2) |
| engine `write.rs:899` "takes it out of its groups" | goes |
| engine `undo/mod.rs:672` removed from every `group.0` | goes |
| engine `rotation/tests_stranded.rs:55` `group(&mut lp, 2)`: a thing with own secrets | sync unit |
| osis `port/client.rs:622` `GroupSync` per thing | sync unit |
| osis `tests/it/undo.rs:448` `&group` (the AK) | goes |
| osis `tests/it/api.rs:1315` `w.group(h).add(Item)`, `:1025` "the group's content" | holds.0 (2) |
| sync `tests/it/leave.rs:550` lists group as a subgroup | closure |
| sync `tests/it/siblings.rs:453` "its synced group" | goes |
| sync `tests/it/flows.rs:1252` "in a group" | closure |
| blob `blob.rs:487` delete-key groups, `step.rs:435` test `Group` secrets | other (2) |
| crdt `state.rs:350`, commit `tests/build.rs:239` `prefix_groups` | other (2) |
| kit `tests/it/view_costs.rs:35` `x.group(tag)` | tag |
| kit `store.rs:98` "the group writes go to" (`main_group`) | holds.0 |
| app `tests/it/fields.rs:12` `group.0` hidden | goes |
| app `demo.rs:97` favorites on the main group | holds.0 |
| cli `args.rs:67` `group add`, `cmd.rs:836` `subgroup_of` | goes (2) |
| spec permissions.md L10 "member of a group" | goes |
| spec permissions.md L168 "no group sync ID" | sync unit |
| spec wire.md L160 delete-key group | other |
| spec sync-set.md L30 "a `group.0` change" | closure |
| notes/engine.md L60 memo `Group` | other |
| notes/client-port.md L58 "a foreign group" (an actor) | sync unit |
| notes/test-scale.md L23 group membership scale row | goes |

Tally: goes 11, other 7, sync unit 4, holds.0 4, closure 3, tag 1. Calibration: about a quarter of hits are the other sense and must not be touched; a rename by search would hit them.

## 5. Baselines (515e499c5)
- `tools/loc.py`: 140,433 source, 120,784 test (equal to the plan's 1d3d94ac7 figures). Per crate (source/test): engine 37,118/47,586, sync 16,093/18,264, crdt 11,558/10,232, kit 9,971/3,226, roles-model 9,714/2,430, osis 9,110/9,099, perm 5,554/5,386, store 4,616/3,159, crdt-model 4,342/1,253, base 4,138/1,864, transport 3,970/2,489, cli 3,654/1,008, schema 3,305/1,059, held-model 2,682/3,255, vectors 2,271/78, commit 2,239/1,940, keys 1,776/2,578, proto 1,654/1,068, crypto 1,562/835, blob 1,546/1,130, app 1,227/1,942, sim 1,092/98, android 873/0, chat 184/262, bench 184/187, fuzz 0/356.
- Default tests, as recorded (not run): CLAUDE.md "about 6.5-9 min and 4700-5300 CPU-s built"; notes/build.md `default-tests` "1190 / 123 s at load 16"; notes/time-limits.md "default tests 1150-1350 CPU-s against 1183" (fastbox-0); issues/test-time.md "Per test (`tools/pertest.py`, 3,251 tests, 9,379 G)". No note records a current count; statically there are 3,683 `#[test]` functions and 91 `#[ignore`. The demolition should run `tools/pertest.py run` first for a count and instructions it can compare.
- Removable, est. (source / test):
  | mechanism | source | test |
  |---|---|---|
  | lifetimes (held-model 264 + 330 included) | 750 | 1,100 |
  | synced groups, shared here | 250 | 1,200 |
  | groups, `Groups`, `Write::group` | 1,200 | 4,000 |
  | tied grants | 350 | 500 |
  | invitations (blobs, taking, copies, acted, list) | 2,200 | 1,900 |
  | `kept^.0` | 250 | 750 |
  | refs exclusions, caps/clients move, tid tag | ~0 (edits) | ~0 |
  | total | about 5,000 | about 8,000-9,000 |
  Tests overlap between rows; the total counts each once (7,500 named plus helpers, the differential and sims). Source error: perhaps 30% either way.

## 6. Not verified, and surprises
- **The tid tag is not deletable alone.** `Value::Tid` (320 sites) is how every tid inside a value is encoded, including creation records and `roles.0` keys; the plan has them hold weaks. Deleting it in demolition leaves those without an encoding: the demolition must either do lane (a)'s type change or leave the tag to lane (a). The coordinator's call.
- **`Groups` is the sync closure and the key home.** Nothing syncs after it goes, and most sync tests sync by D's derived items (a thing made under D is carried), which the plan also removes; they compile but stop syncing. Count them by running, not by grep.
- **`sync/src/life.rs` holds four duties**; only lifetimes and tied grants go.
- **Stamping in place** is shared with deposit promotion (`read/ground.rs`, `read/judge.rs`, `store`): only the inbox-blob case goes.
- **Grant copies** are certificate copies in the required set (`sync_ids/certs.rs`), inside machinery that stays.
- **Inbox deliveries carry more than grants**: rotations' boxes to sync-only holders, removals, re-seals (`sync/deliveries.rs`, `flows/edges.rs`). After demolition a sync-only holder gets no new keys until lane (c) fires fresh tickets on key changes (plan Tickets, An old ticket).
- **Not in the plan**: `StrandedNotice`, the third inbox blob kind (spec/permissions.md §4 Stranded; sent to admins' inboxes by `core/sync/src/inbox/stranded.rs`), which the plan sends over connections only (spec/permissions.md §4 Stranded); `keys.0` `inbox` (an actor's inbox sync ID), which an inbox thing per account would replace; invite requests (spec/sync-inbox.md L31); `records::Offer` (rows `io/`); the group source of spec/sync-set.md (§5, now Source) and `GroupSource`, `group_sources` (stays, renamed for sync units); `Osis::home()` as D; `SyncScope::Deliveries`; `GroupSync`; `tools/spec_map.py` rows; spec/requirements.md L7, L10, L28, L44, L49-58, L77, L96, L123, L132 speak of groups (Tess's sign-off).
- issues/app-group-helper.md speaks of groups (its duplicates problem stays); issues/storage-follows-groups.md is the plan's input.
- Not verified: how `caps^.0`/`clients^.0` stay off the wire (inferred above); the per-function line estimates.
