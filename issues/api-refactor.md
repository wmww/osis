# Refactor the public API
> Summary: Every change proposed to the `osis` crate's public API after a whole-API review against notes/api-design.md: target feel, decisions for Tess, then removals, merges, reshapes, leaks and renames, plus execution order. Not started; hold until the decisions are answered and in-flight core work allows. Absorbs the former issues/api-review.md.
> Tags: api, cli, naming

Reviewed at main 853f28fc, signatures and doc comments of everything `core/osis/src/lib.rs` exports. "Verified" facts below come from reading the code. No proposal here has been compiled or tried; expect some to meet obstacles, and judge those by notes/api-design.md rather than dropping them quietly. Usage counts came from a grep by method name and are only rough.

## Target feel
Every data operation is addressed the same way, groups read like aspects, and sharing has one verb per intent:
```rust
let db = Osis::open(Store::Dir(path), Config::default())?;

let mut w = db.write();
let note = w.create()?;                                    // first admin: this account (owner removal)
w.group(folder).add(Member::Item(note))?;
w.at(note, notes::TITLE).set(&title)?;
w.at(note, notes::TAGS).path(p![&tag]).set(&true)?;
w.at(msg, chat::BODY).expires(Expiry::In(DAY)).set(&text)?;
let done = w.commit()?;

let title = db.at(note, notes::TITLE).get()?;
let sub = db.at(note, notes::TITLE).on_change(|db, c| ..)?;
let text = db.at(note, notes::BODY).edit_text()?;

db.grant(note, friend, Role::Write, GrantOpts::default())?;
db.demote(note, friend, Role::Read, SyncFirst::Required).await?;
db.remove_holder(note, friend, Removal::default()).await?;
```

## Decisions for Tess
Recommendation first in each. Everything else below is the agent's call unless she objects.
1. **`grant` and `share`** (B1). Make `grant` always ensure a route, and remove today's route-less `grant`. This reverses "records the permission and nothing else" (her decision, notes/api.md Sharing). Alternative: keep both.
2. **Read and write entry points** (A1, A2). Remove `db.get` and `write_with`: one spelling, slightly longer. Alternative: keep one convenience as a named exception.
3. **Pull-style `Watch`** (A3). Remove it, leaving callbacks only. Alternative: keep it if async apps want `changed().await`; then it needs a stated reason.
4. **`db.read(|r| ..)`** (A4). Move it to `internals`. No first-party app, chat or CLI code calls it, and it fails on attached handles. Alternative: keep it and give it the same methods as `Osis`.
5. **ID names** (F). `Tid` to `ThingId`, `Ak` to `AspectName`. High churn, clearer to read. Alternative: keep the short names and document them.
6. **"Placement" wording** (F). As in the old api-review: a thing is a member of a group. `Item` and `Subgroup` name the two kinds.

## A. Remove: a second way to do the same thing
1. `Osis::get` duplicates `at(t, k).get()`. `at` is the one that extends to paths, streams and watches.
2. `write_with` duplicates `write()` + `commit()` and hides the `Committed`. Dropping a `Write` already discards it.
3. `AspectRef::watch`, `Watch` and `Changed`: `on_change` covers these with a channel (decision 3). `Watch` alone has three wait methods (`changed`, `try_changed`, `changed_timeout`).
4. `read` and `Reader`: a second copy of about ten read calls with different argument styles (decision 4).
5. `get_value` on `AspectRef` and `PathRef`: use an untyped key, or `path(p).get::<Value>()` (`Value` is `Codec`).
6. `home()`: verified always the same tid as `me()`, locally, attached and acting. Document that an account is a group.
7. `AspectWrite::inc`: same as `path(Path::root()).inc`.
8. `PathWrite` ops that are verified the same op under another name:
   - `observe` is `inc` (both `Op::Inc`). Keep one, named for both uses, say `add_to`? Pick when building, avoiding a clash with set `add`.
   - `put(k, v)` is `path(k).set(v)`.
   - `remove_key(k)` and `remove_elem(v)` are `path(k).remove()`.
   - `set_case` is a `set` of a `Value::Enum`.
9. Whole-value ops at an empty path (`at(k).path(p![]).set`, `.replace`, `.remove`) duplicate `at(k).set` and friends. Refuse them, or make `AspectWrite` the only route to them; the collection ops still take an empty path.
10. Writing `core::GROUP` directly: `w.at(g, GROUP)` path ops and `.set` bypass `place`'s sync check and tied-edge cleanup (tests do it). Refuse it as role-class aspects are refused, and add `items(g)` and `subgroups(g)` for reading. Today's way to list a group's items is `get(g, GROUP)` (notes/api.md, tests), so callers move to those.
11. `TextSession::insert` and `delete` are `replace` with an empty side. Keep `replace(range, text)`.
12. `all_links` and `links(target)`: keep `links()` returning all; `LinkInfo.target` filters.
13. `Config::at` duplicates `memory`, `dir` and the struct (see D1).
14. `set_keep_default`: a one-line wrapper over `at(t, REQUIRED).set`, while required retention itself has no call of its own. One rule for both: pick typed calls for all required rules, or none.
15. `materialize_limit()` getter: no callers.
16. `ShareOpts.place_anyway` is `place` itself (see B3).
17. `demote` following a link joiner into `revoke_joiner`: keep one route (see B2).
18. `attach_client` is `attach_remotes` with one entry (see D2).
19. `register_schema_file` and `register_schema_source`: parse then register. Worse than a duplicate, they differ: only `_source` mirrors the schema to an attached node, so `register_schema(Schema)` silently doesn't (verified). One `register_schema(source)`; `Schema` stays out of the API if the parsed form has no other use. Reading a file is the app's job.

## B. Sharing: one verb per intent
Today: `grant`, `share`, `share_into`, `change_edge`, `demote(Lower)`, `leave`, `remove_edge_of`, `remove_device`, `remove_client`, `revoke_link`, `revoke_joiner`.
1. **`grant(target, holder, role, GrantOpts)`** is the one call that adds, raises or changes `until` and `invite`, and it ensures a route as `share` does today (decision 1). Removes `share` and `change_edge`. `change_edge` is `grant` plus a refusal to lower. `grant` itself should refuse lowering too. From reading `Osis::grant` and `grant_in`, neither checks, so a `grant` at a lower role looks like it lowers with no pre-sync and no rotation. Not run: write a failing test first. If confirmed, it is a bug whichever way decision 1 goes.
2. **Demote and remove become separate functions.** `demote(.., Lower::{To, Remove}, Demotion)` is centered wrongly: the two cases differ in what is allowed (a joiner can only be removed) and what applies (`keep` only on removal).
   - `demote(target, holder, role, SyncFirst)`.
   - `remove_holder(target, holder, Removal { sync: SyncFirst, keep })`.
   - `repudiate(target, holder)` as its own call: today's `Demotion.repudiate` is a rare recovery with its own rules ("a direct edge only", "only after a lockout").
   - Decide whether removing a link joiner stays in `remove_holder` or is only `revoke_joiner`; one route.
3. **`share_into`** stays as "add to a group and let its holders in", without `ShareOpts`: `share_into(member: Member, group, role)`. `place_anyway` goes: an app that wants it calls `Write::group(..).add`. It returns nothing unless an app needs `Share`; `reach` answers that.
4. **`leave(target)` and `remove_edge_of(group, target)`** are both self-removals: one `leave(holder, target)`, with `me()` as the usual holder.
5. **`remove_device` and `remove_client`**: both a removal of a holder of the account plus cleanup. Keep them, but give each the same `Removal` shape where it applies; `remove_client` is sync and takes none, and that difference should be justified or removed.
6. **`Share::{Tied, Untied, Excluded}`, `Edge.tied`, `GroupReach`, `reach`, `holder_path`**: tie and path are internals. Keep a way to answer "who can get at this, through what, and will it go when the membership goes", in plain words: `via_group` on a grant, say. `holder_path` is used by chat, and the old api-review notes the missing reverse ("who holds through this"), so design one `holders(target)` answering both.
7. **Links**: `LinkInfo.id` is documented as "the link's actor K"; make an opaque `LinkId`. `revoke_joiner` is named for link internals; `joiner` is fine, but see B2.

## C. Reads that hide failure (robustness)
Verified: `groups_of`, `knows`, `role_on`, `roster`, `owner_of`, `created`, `changed`, `reach`, `holder_path`, `links`, `hosts`, `hosting`, `host_key`, `routes`, `watch_thing`, `watch_roster`, `watch_status` cannot return an error, so on an attached handle a lost connection gives an empty default plus a diagnostic (notes/client-port.md §1 states this as the rule). So `knows` says a thing is gone and `roster` says nobody holds it when in fact the node is unreachable, against "a disconnected source is `Network`". `demote` itself walks `holder_path` and `roster`. All become `Result`.

Also:
- `knows` conflates "no content yet" and "deleted" (issues/api-knows-empty.md). Fix it here.
- `Osis::close` reports a normal outcome as `Err(StillOpen)` after closing the handle.
- `sync(group, hosts)` is verified a silent no-op when a label exists, even with different hosts. Make it refuse, or change them.
- Default `Runtime::None` with `Config.hosts` set means nothing syncs and nothing says so. Refuse that, or default to `Own`.
- Without feature `iroh`, `Config.peers` and `relays` silently do little.
- `Unsupported` means both "not built yet" and, from `attach_client`, "the node refused your secret". Give the refusal its own variant; `Unsupported` means only "this kind of handle doesn't carry this call".
- `aspects(t)` may omit a register whose last write was purged (old api-review). Decide and document.

## D. Shape, re-decided
Each is a fresh verdict by the tests in notes/api-design.md, including those that stay.

Change:
1. **`Config` as one struct for every constructor** → required inputs become arguments. `hosts` is read only by `create`, `restore` and `pair`; `store` is ignored by every `attach*`; `remotes` by most. `Osis::create(Store, hosts, Config)`, `open(Store, Config)`, and so on; `Config` holds only what applies everywhere, with `Default`. `clock` and `seed` move to `internals`.
2. **`attach`, `attach_client`, `attach_remotes`, `attach_node`** → `Osis::connect_socket(path, Config)` and `Osis::connect(&[NodeLogin], Config)`, plus `db.attach_node` and `detach_node` for a handle with a store. `is_attached` is misnamed: it is false on a handle with `attach_node` attachments (verified). Rename it `has_store`, inverted.
3. **Expiry**: `expires_at`, `expires_in`, `expires(Option)` → `.expires(Expiry::{At, In})`. Not calling it means the key's default.
4. **Group ops** → a `w.group(g)` builder like `w.at`: `.expires(e)`, `.add(Member)`, `.remove(Member)`. `Member::{Item, Subgroup}` replaces `place`, `place_expiring`, `unplace`, `add_subgroup`, `remove_subgroup` and `ShareOpts.subgroup`. `make_group` stays a question: can a group just exist on first member? It affects "is this a group", so check `require_synced` before deciding.
5. **Sequence ops** → one `splice(range, items)`, generic over list items and `&str`, replaces `insert`, `delete` and text `splice`.
6. **Purge**: `purge`, `purge_commit`, `purge_author` → `purge(Purge::{All, Change(id), Author(actor)})`. Same action, different targets. Note `All` also removes the aspect; keep that visible in its doc.
7. **`Demotion`** → fields override each other (`backdate` beats `sync`), so merge them into an enum: `SyncFirst::{Required, Try(d), Skip, Backdate(t)}`.
8. **`CommitQuery`**: builder and public fields are two ways, and `next` changes the contract ("needs a scope", "not with `after`", new failure). Plain struct with `Default`, like the other options. `next` becomes `undo_target(&scope)` and `redo_target(&scope)`; `Next` goes. `actor(a)` adds to `actors`: one spelling.
9. **`Committed { id, ts, also }`** → `changes: Vec<ChangeId>` (first carries the record), `ts`. Today `id` and `also` differ in type for no gain.
10. **`GroupPolicy`**: a whole-replacement struct with `publish_reach: Option<bool>`. `None` is a third state, so make it `Reach::{Auto, Always, Never}`. Getter and setter have unrelated names (`group_policy`, `sync_policy`): `sync_options` and `set_sync_options`. `receipts_only` → `SyncMode::{Full, HeadersOnly}`.
11. **`Hosting.policy: BTreeMap<String, u64>`** → a typed struct; unknown names then cannot exist at run time. `listen: Vec<String>`, `client_listen(&[String])` and `relays` → a URL type, or at least consistent with `Address`.
12. **`Diagnostic { kind, tids, commit, peer, detail }`**: the meaning of `tids` depends on `kind` (documented positionally: "`tids`: item, group") → an enum with named fields per kind.
13. **`Stamp` and `CommitInfo`**: verified the same fields but for `Option<CommitId>` vs `ChangeId`, and only `Stamp` has `shown()`. One type.
14. **`SyncScope::Group(t)`** takes any thing → `SyncScope::{All, Thing(t)}`, matching `Scope`.
15. **Waiting**: `wait_synced` takes a timeout, `redeem` and others use `Config.wait_timeout`, demotions use constant `PRESYNC_WAIT` or `Try(d)`. Every `async` call takes one explicit timeout, and the constant and config field go. Check the attach dial, which needs a value too.
16. **`edit_text(tid, key, path)` and `keep_alive(tid, key, path, v)`** take positions differently from everything else → `at(t, k).path(p).edit_text()` and `.keep_alive(v)`.
17. **Callback naming**: `watch_*` take a callback here but `watch()` returns a handle there. All callbacks are `on_*`: `on_thing_change`, `on_roster_change`, `on_status_change`, `on_change`, `on_history`, `on_diagnostic`. All return `Result<Subscription>` and all get `&Osis`; `TextSession::on_remote` currently does neither.
18. **`AspectKey`**: three implementations (`Aspect<T>`, `Ak`, `Key`) plus `db.key`. `Key` with no schema is `Ak`. One dynamic key: `db.key(name)` typed when a schema is registered, else untyped. `Ak` becomes a name only, if the examples stay readable. The trait's methods exist for generated code and the crate: seal it or hide them.
19. **`LinkOpts`, `GrantOpts` and `Removal`** stay structs, but `..Default::default()` should work on all three; `LinkOpts` is spelled out in full in the crate docs today.

Keep as they are:
- `undo` and `redo` as two functions: different results, no shared target to enum over.
- `Dispatcher`, `Runtime`, `StoreAt` (renamed `Store`), `HistoryFrom`, `HistoryBody`, `HistoryEvent`, `Scope`, `SyncState` as enums.
- Signals as a lifetime marker on an aspect key: no extra call, the simplest thing in the API.
- One `Osis` type with `Unsupported` on calls a kind of handle doesn't carry (Tess's decision against a second client type). Each such call's doc must say so.
- A flat method list on `Osis` rather than namespaces (`db.sharing()`, ...): that would add concepts.
- `settle` for both pump and test wait: same operation, though `run_callbacks` may read better.

## E. Leaks
- **Exported implementation numbers**: `MAX_CONNS_PER_CLIENT`, `HISTORY_DIRTY_BYTES`, `HISTORY_SEND`, `MAX_SCHEMA_BYTES`, `SIGNAL_BYTES`, `STREAM_CHUNK`, `WRITE_NONCES`, `REFRESH_DIVISOR`, `OFFER_LIFETIME_MS`, `PRESYNC_WAIT`, `DEFAULT_*`. Make them private or move them to `internals` for tests. `HISTORY_PAGE` stays only if a page limit is the caller's business.
- **Socket helpers**: `socket_path`, `SOCK_FILE`, `own_uid`, `socket_dir`: the CLI's needs, not an app's. `connect_socket(store_dir)` can resolve the path itself.
- **Test tools in app API**: `MemStore::{held_bytes, rows, held_split, backup}`, `Transport::InProcess`, `ManualClock`, `Clock`, `Config.seed`, `Config.clock`, `Joining::node`. `Transport` itself may go, leaving what the app really chooses.
- **`osis::core`**: re-exports `KEYS`, `SECRETS`, `LABEL`, `ROLES`, `TENURES`, `REACH`, `SEEN`, `NODE`, `PLACED`, `GROUPS`, `ASPECTS`, `TID`, `group::{ITEMS, SUBGROUPS}`. Keep `NAME`, `BODY`, `TAG`, whatever else apps truly write, and required-retention if decided in A14.
- **`pub use osis_schema as schema`** exports the whole crate for generated code. Give generated code a narrow doc-hidden path.
- **`CreationRecord`, `Cause`, `EphemeralId`, `CommitId` beside `ChangeId`, `LabelId`**:
  - One opaque `ChangeId`.
  - `Source::Derived(Cause)` has `LateDelta`, `Validity` and so on: keep `Derived` with a small plain reason, or none.
- **`Ts`** is a hybrid clock value, exposed in `Stamp`, `CommitInfo`, `Committed` and `CommitQuery.since` next to `WallMs`. One `Time` type for apps; ordering is opaque in `HistoryPos`.
- **`CommitKind::{Role, Snapshot}`**, `HistoryBody::Dropped`, `CommitEntry.dropped`: "snapshot" is compaction. Keep what an app must see to explain history (notes/api.md Attribution), and rename it in plain words.
- **Sync status**: `GroupSync.labels`, `not_admitted`, `Stranded`, `ReceiptsOnly`, `NoRoute`, `unrouted`, `Status.split`. Labels are needed to configure hosts, so call them what they are for hosts (`host_ids`?) and keep them with hosting.
- **Other words to translate or hide**: `rotate_reach`, `publish_reach`, `rotate_client_key`, `backdate`, `repudiate`, `materialize_limit`, `tied`, "pre-sync", "co-reader", "K", "L".
- **`Key::new(ak, schema)`** and `Schema` in the public API: see A19 and D18.
- **`KeepAlive::writes`** doc-hidden on an app type: move to `internals`.

## F. Names
| Now | Proposed | Why |
|---|---|---|
| `HostAddr` (also names nodes: `attach_client`, `client_listen`, `RemoteConfig`) | `Address` | It is not always a host. This is Tess's server/host example turned around. |
| `RemoteStatus.address: String`, `routes() -> map<Tid, String>` | `Address` | One type |
| `RemoteConfig` | `NodeLogin` | It is an address and a secret |
| remote, attachment, route, source | "attached node", "route" | Four words for two ideas |
| `Device.node`, `node()`, `devices()`, `remove_device(node)` | pick `device` for the API | Same thing, two words |
| `Source` (why a watch fired) | `Origin` | Collides with sources per group; notes already say `Origin` |
| `DropReason` | `NotUndoableReason` | It is why a revert fails |
| `at.len()`, `path.len()` | `byte_len()` | It is canonical size in bytes, not element count |
| `Lower` | gone (B2) | |
| `Edge`, `EdgeOpts`, `change_edge` | `Grant`, `GrantOpts` | issues/grant-rename-multi-actor.md |
| person, "person actor" | account | issues/account-rename.md |
| `sync_now` | `nudge_sync`? | It nudges; `wait_synced` is what syncs |
| `make_link`, `redeem`, `import_contact` | keep | Clear |
| `hosts()`, `hosting()`, `host_address()` | `hosts()` and `own_host_*` | The hosts this account uses vs the host this node runs |
| `create_ownerless`, `owner_of`, `create(owner)` | `create(first_admin)` or `create()` | Owner removal; don't design twice |
| `place*`, `placed` | decision 6 | |
| `Tid`, `Ak` | decision 5 | |

## G. From building osis-chat (old api-review, not re-checked)
- `replace` of a `Value::Map` on a long aspect costs a write O(writes so far); a scalar stays flat. Nothing says so.
- `set` of an equal value writes nothing, so `at.set` silently loses a repeated message on a kept-write aspect, which must use `replace`. Not wrong, but it is the first thing one reaches for. Look at it together with `set` vs `replace` naming: the two names don't say how they differ.
- No `at.history_entry(id)`: a lookup is a walk from `After(HistoryPos::time(ts))`, so an id must carry its `ts` and aspect.
- `on_history` is per aspect, so a per-year chat holds one subscription per year, none for a year beyond next.
- `HistoryBody::Purged { by }` once needed a commit query with no by-id filter; check it's solved by `actor`.

## H. Docs and crate layout
- `core/chat` should leave core: plenty of core users don't need chat, and notes/build.md already says further projects are top-level directories depending only on `osis`. Recommend top-level `chat/`, unless more helper libraries appear (then a directory for them). `core/*` in the workspace members and paths in notes, gate and policy tools change with it.
- Crate docs after the refactor: rewrite `lib.rs` sections to the Public docs rules in notes/api-design.md, since most examples change anyway. "Footguns closed" is the first to go or become plain advice. Module-level jargon in the first lines of each section ("placement is a group op") likewise.
- Rendered docs still cite `spec/` as plain text (about 90 lines, 38 in `share.rs`). Keep those that help a reader, drop the rest. To make them links, a doc-only module could embed the spec with `#[doc = include_str!(..)]`; not tried. Links between spec files would need rewriting, and `tools/gate.sh` runs its full gate on spec edits once Rust reads `spec/`, unless that file joins its docs step.

## Related issues, resolve within this work
- issues/api-knows-empty.md, issues/api-leaving-give-up.md (a give-up call belongs with `leave`), issues/account-rename.md, issues/grant-rename-multi-actor.md (public `act_as(actor) -> Osis` could replace `Write::act_as`).
- issues/api-deferred.md stays for what isn't built, but its shapes should follow this design. `Unsupported` shouldn't cover unbuilt calls: an unbuilt call isn't in the API.

## Execution
- **Timing**: owner removal (notes/owner-removal-plan.md) removes `owner`, `owner_of`, `create_ownerless` and `Class::Chain`, and whole commits is in flight. Coordinate with notes/handoff.md. Skip the owner names here if that work hasn't landed, and don't rename what it deletes.
- **Order**, one branch per step, each passing `tools/gate.sh`:
  1. C and the `grant`-lowering bug, the only behavior fixes.
  2. A (removals).
  3. B (sharing).
  4. D (shapes).
  5. E (leaks), once `internals` has what tests need.
  6. F (renames), last, as one mechanical branch, since they conflict with everything.
- **Each step also updates**: the port rows and codec (`core/osis/src/port`; formats change in place, no compatibility), `cli/`, `core/chat`, `app/` and `kit/` (own workspace), `core/test/sim`, tests, `lib.rs` doc examples, notes/api.md, notes/client-port.md and spec words where the spec uses a renamed term.
- Check each result against notes/api-design.md, and have a fresh reviewer read the final export list in `lib.rs` as a whole.
