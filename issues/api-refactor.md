# Refactor the public API
> Summary: Every change proposed to the `osis` crate's public API after a whole-API review against notes/api-design.md: target feel, decisions for Tess, then removals, merges, reshapes, leaks and renames, plus execution order. Not started; hold until the decisions are answered and in-flight core work allows. Absorbs the former issues/api-review.md.
> Tags: api, cli, naming

Reviewed at main 853f28fc, signatures and doc comments of everything `core/osis/src/lib.rs` exports. "Verified" facts below come from reading the code. No proposal here has been compiled or tried; expect some to meet obstacles, and judge those by notes/api-design.md rather than dropping them quietly. Usage counts came from a grep by method name and are only rough.

## Target feel
Every data operation is addressed the same way, groups read like aspects, and sharing has one verb per intent:
```rust
let db = Osis::open(Store::Dir(path), Config::default())?;

let mut w = db.write();
let note = w.create()?;                                    // first admin: the acting actor
w.group(folder).add(Member::Item(note))?;
w.at(note, notes::TITLE).set(&title)?;
w.at(note, notes::TAGS).path(p![&tag]).set(&true)?;
w.at(msg, chat::BODY).expires(Expiry::In(DAY)).set(&text)?;
let done = w.commit()?;

let title = db.at(note, notes::TITLE).get()?;
let sub = db.at(note, notes::TITLE).on_change(|db, c| ..)?;
let text = db.at(note, notes::BODY).edit_text()?;

db.sync(note, &[])?;                                       // only if no synced group carries it
db.grant(note, friend, Role::Write, GrantOpts::default())?;
db.set_role(note, friend, Role::Read, SetRole::default()).await?;
db.revoke(note, friend, Revocation::default()).await?;
```

## Decided
Tess answered; the refactor is now in progress (Execution, below).
1. **`grant` and `share`: not bundled.** A role says who may; `sync` says where the data goes. `share` goes; `grant` only grants, as before, and refuses to lower. Chat's one `share` is on an already synced chat and the app only grants, so real callers lose nothing; tests and the CLI call `sync` then `grant`. `grant`'s doc and `status` (`NoRoute`) must make a holder with no way to the data obvious. `make_link` keeps syncing its target, as a link can't work otherwise. Revisit if the app finds this awkward.
2. **One spelling**: `db.get` and `write_with` go. The agent makes such calls without asking.
3. **`Watch` goes.** `on_change` gives the current value atomically, then changes, and works with any async runtime by forwarding to a channel. Show that in the docs. Revisit only if using it from async code proves clumsy.
4. **`db.read(|r| ..)`** moves to `internals`.
5. **`Tid` stays**: a tid is a concept and is not called a thing ID. **`Ak` stays**: renaming it would sweep every crate for little gain.
6. **Member**: a thing is a member of a group. `osis-chat`'s members become participants.
7. **Layout**: top-level `libs/` holds `chat` and `kit`, and whatever else is useful to some but not all users of osis. `app/` and `cli/` stay where they are.

### Owner removal is in progress elsewhere
Design for the world after it:
- **`create()` takes no owner and `owner_of` goes.** The first admin is the acting actor. Until owners are gone, whatever still needs one is doc-hidden and marked for removal: `create_owned_by(owner)`, `create_ownerless(admin)`, `owner_of`.
- **Leave room for dispute calls** (list, listen, choose). They are per-node trust choices, not data writes: plain calls on `Osis` (`disputes()`, `on_dispute(f)`, `choose_side(..)`), nothing on `Write`. Not built here, but nothing should block them.
- **Don't touch engine or perm internals** for renames: the owner work is in there. Rename at the `osis` API, CLI and docs; leave engine names, and spec prose the owner work is rewriting, for a last sweep.

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
All of this speaks of granting a role (F, Vocabulary). Today: `grant`, `share`, `share_into`, `change_edge`, `demote(Lower)`, `leave`, `remove_edge_of`, `remove_device`, `remove_client`, `revoke_link`, `revoke_joiner`.
1. **`grant(target, holder, role, GrantOpts)`** is the one call that adds, raises or changes `until` and `invite`, and nothing else (Decided 1). Removes `share` and `change_edge`. `grant` refuses lowering (done).
2. **Demote and remove become separate functions.** `demote(.., Lower::{To, Remove}, Demotion)` is centered wrongly: the two cases differ in what is allowed (a joiner can only be removed) and what applies (`keep` only on removal).
   - `set_role(target, holder, role, SetRole { sync: SyncFirst, until, invite })`, async: makes the holder's role this one, raising or lowering. The usual call (Tess). Replaces lowering by `demote`; a link joiner's role still can't be lowered (`Invalid`).
   - `grant` stays beside it, the one justified overlap: it never waits and never takes anything away, for sync code and for callers that mean only that. Say so at its definition.
   - `revoke(target, holder, Revocation { sync: SyncFirst, keep })`, the natural opposite of `grant`.
   - `repudiate(target, holder)` as its own call: today's `Demotion.repudiate` is a rare recovery with its own rules ("a direct edge only", "only after a lockout").
   - Decide whether removing a link joiner stays in `revoke` or is only `revoke_joiner`; one route.
3. **`share_into`** stays as "add to a group and let its holders in", without `ShareOpts`: `share_into(member: Member, group, role)`. `place_anyway` goes: an app that wants it calls `Write::group(..).add`. It returns nothing unless an app needs `Share`; `reach` answers that.
4. **`leave(target)` and `remove_edge_of(group, target)`** are both self-removals: one `leave(holder, target)`, with `me()` as the usual holder.
5. **`remove_device` and `remove_client`**: both a removal of a holder of the account plus cleanup. Keep them, but give each the same `Revocation` shape where it applies; `remove_client` is sync and takes none, and that difference should be justified or removed.
6. **`Share::{Tied, Untied, Excluded}`, `Edge.tied`, `GroupReach`, `reach`, `holder_path`**: tie and path are internals. Keep a way to answer "who can get at this, through what, and will it go when the membership goes", in plain words: `via_group` on a grant, say. `holder_path` is used by chat, and the old api-review notes the missing reverse ("who holds through this"), so design one `holders(target)` answering both.
7. **Links**: `LinkInfo.id` is documented as "the link's actor K"; make an opaque `LinkId`. `revoke_joiner` is named for link internals; `joiner` is fine, but see B2.

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
19. **`LinkOpts`, `GrantOpts` and `Revocation`** stay structs, but `..Default::default()` should work on all three; `LinkOpts` is spelled out in full in the crate docs today.
20. **`now()`** on an attached handle that cannot reach its node falls back to this process's clock, unsaid. A time is no decision-maker's default, but it should say so or return `Result`.

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
| `knows` | `has_content` | What it answers: a thing created and not yet written is known here, and reads `false` |
| `at.len()`, `path.len()` | `byte_len()` | It is canonical size in bytes, not element count |
| `Lower` | gone (B2) | |
| `Edge`, `EdgeOpts`, `change_edge` | `Grant`, `GrantOpts` | issues/grant-rename-multi-actor.md |
| person, "person actor", `Person`, `PERSON` | account | Decided: issues/account-rename.md |
| `sync_now` | `nudge_sync`? | It nudges; `wait_synced` is what syncs |
| `make_link`, `redeem`, `import_contact` | keep | Clear |
| `hosts()`, `hosting()`, `host_address()` | `hosts()` and `own_host_*` | The hosts this account uses vs the host this node runs |
| `create_ownerless`, `owner_of`, `create(owner)` | `create(first_admin)` or `create()` | Owner removal; don't design twice |
| `place*`, `unplace`, `placed.0~`, `PlacementNotPersisted`, `place_plan` | `add`, `remove`, membership words | decision 6 |
| `demote`, `Demotion` | `set_role`, `SyncFirst` | B2 |
| `roster`, `Roster`, `watch_roster` | `grants(target)` | The word for a list of grants |

### Vocabulary
- **Account**, not person or user: an account may be a team, a bot or a shared identity. `me()` keeps its name.
- **Roles**: one sentence for all of it: an actor is *granted a role* on a thing, and is then a *holder* of that role. A role can be set, or revoked. Clean out older words wherever API, CLI, spec and notes use them:
  - *edge* for a grant (70 lines in `core/osis/src`, 131 in `spec/`), including "tied edge", `EdgeKey` and the CLI's `edge`.
  - *rights* where a role is meant, *demotion* and *removal* for a revocation (55 and more lines). `Error::Permission` may stay as the general word, or become `NeedsRole`.
  - *entitlement* and *tenure*: internal, keep them out of anything public; the spec may keep what it must define.
  - *share*: only for a composite that also gives access (`share_into`), or dropped with it. `Share::{Tied, Untied, Excluded}` follows B6.
- **Membership**: being in a group grants nothing (spec/permissions.md §1 already says so) and a thing can be in many groups. The docs must keep "a group's members" (what it contains) clearly apart from "a group's holders" (who has a role on it), since people will confuse them. Sync's other "placed" (a commit held at a host, spec/sync.md §5) becomes "uploaded" or "at a host".

## G. From building osis-chat (old api-review, not re-checked)
- `replace` of a `Value::Map` on a long aspect costs a write O(writes so far); a scalar stays flat. Nothing says so.
- `set` of an equal value writes nothing, so `at.set` silently loses a repeated message on a kept-write aspect, which must use `replace`. Not wrong, but it is the first thing one reaches for. Look at it together with `set` vs `replace` naming: the two names don't say how they differ.
- No `at.history_entry(id)`: a lookup is a walk from `After(HistoryPos::time(ts))`, so an id must carry its `ts` and aspect.
- `on_history` is per aspect, so a per-year chat holds one subscription per year, none for a year beyond next.
- `HistoryBody::Purged { by }` once needed a commit query with no by-id filter; check it's solved by `actor`.

## H. Docs
- Crate docs after the refactor: rewrite `lib.rs` sections to the Public docs rules in notes/api-design.md, since most examples change anyway. "Footguns closed" is the first to go or become plain advice. Module-level jargon in the first lines of each section ("placement is a group op") likewise.
- Rendered docs still cite `spec/` as plain text (about 90 lines, 38 in `share.rs`). Keep those that help a reader, drop the rest. To make them links, a doc-only module could embed the spec with `#[doc = include_str!(..)]`; not tried. Links between spec files would need rewriting, and `tools/gate.sh` runs its full gate on spec edits once Rust reads `spec/`, unless that file joins its docs step.

## Related issues, resolve within this work
- issues/api-leaving-give-up.md (a give-up call belongs with `leave`), issues/account-rename.md, issues/grant-rename-multi-actor.md (public `act_as(actor) -> Osis` could replace `Write::act_as`).
- issues/api-deferred.md stays for what isn't built, but its shapes should follow this design.

## Execution
One branch per step, in order; each merges before the next starts.
- **2. Removals**: A.
- **3. Sharing**: B.
- **4. Shapes**: D.
- **5. Leaks**: E, once `internals` has what tests need.
- **6. Names and docs**: F, the Vocabulary, and H's doc rewrite.

Rules for each step's worker:
- Read notes/api-design.md and this issue. The issue is a strong proposal, not a contract: when a change turns out wrong in use, do what the philosophy says and say so in your report. Update this issue: delete what is done.
- **Every consumer moves in the same branch**: `cli/`, chat, `app/` and `libs/kit/` (their own workspace, `libs/kit/Cargo.toml`; see `tools/gate.sh` for its build and test steps), `core/test/sim`, `core/bench`, tests, `lib.rs` doc examples. Port rows and codec change in place: no compatibility. Update notes/api.md, notes/cli.md and notes/client-port.md where they state what changed.
- The CLI mirrors the API: it follows these changes in commands and output too.
- **Using the API from the app and CLI is the test of it.** If a new shape makes them clumsy, fix the shape and report it.
- **Do not loosen an existing test's meaning**: port it. Report any that can't be ported.
- **Behavior bugs**: validate with a test. Fix if simple and low risk, or if it is mostly about implementing the API and doesn't reach deep into core or the apps. Otherwise open an issue.
- Stay out of engine and perm internals (owner removal is working there).
