# Refactor the public API
> Summary: Every change proposed to the `osis` crate's public API after a whole-API review against notes/api-design.md: target feel, decisions for Tess, then removals, merges, reshapes, leaks and renames, plus execution order. Under way, one step at a time (Execution). Absorbs the former issues/api-review.md.
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
let text = db.at(note, notes::BODY).path(p![]).edit_text()?;

db.sync(note, &[])?;                                       // only if no synced group carries it
db.grant(note, friend, Role::Write, GrantOpts::default())?;
db.set_role(note, friend, Some(Role::Read), SetRoleOpts::default()).await?;
db.set_role(note, friend, None, SetRoleOpts::default()).await?;      // no access
```

## Decided
Tess answered; the refactor is now in progress (Execution, below).
1. **`grant` and `share`: not bundled.** A role says who may; `sync` says where the data goes. Done: `share` is gone. `make_link` keeps syncing its target, as a link can't work otherwise. Revisit if the app finds this awkward.
2. **`Tid` stays**: a tid is a concept and is not called a thing ID. **`Ak` stays**: renaming it would sweep every crate for little gain.
3. **Member**: a thing is a member of a group. `osis-chat`'s members become participants.
4. **Layout**: top-level `libs/` holds `chat` and `kit`, and whatever else is useful to some but not all users of osis. `app/` and `cli/` stay where they are.

### Owner removal is in progress elsewhere
Design for the world after it:
- **`create()` takes no owner and `owner_of` goes.** Done but for removing what is doc-hidden and marked (`create_owned_by(owner)`, `create_ownerless(admin)`, `owner_of`, the CLI's `ownerless`) when owners go. Then these need an answer:
  - A thin client: `create()` is `Invalid` (its actor goes with it), so it calls `create_with_admin(g)`: visible, CLI `create --admin G`. Today `g` is its owner. The owner work makes the record name `g` as first admin, and must settle that write on `g` is enough to name it (Tess: see the review of this step).
  - A group's holders: a thing owned by a group is read by the group's holders with no grant (entitlement, spec/sync.md §3): `create_with_admin(g)` too, which after owners holds through `g`'s role on the thing instead. `add_with_grant` stays for what is already made.
  - Tree-of-things: `create_owned_by(x)` in tests, on things that are no actor: goes with owners.
  - Chat tells a person from a team and a link key by `owner_of` (`held_through`, `link_key`); the app's `reach` starts from it. Above, Follows from Sharing.
  - Chat's `create_ownerless(me)` becomes plain `create()` plus a durable write: nothing else in it needs an owner.
- **Leave room for dispute calls** (list, listen, choose). They are per-node trust choices, not data writes: plain calls on `Osis` (`disputes()`, `on_dispute(f)`, `choose_side(..)`), nothing on `Write`. Not built here, but nothing should block them.
- **Don't touch engine or perm internals** for renames: the owner work is in there. Rename at the `osis` API, CLI and docs; leave engine names, and spec prose the owner work is rewriting, for a last sweep.

## A. Remove: a second way to do the same thing
Done but for what later steps own:
- `Config::at` duplicates `memory`, `dir` and the struct: D1.
- `attach_client` is `attach_remotes` with one entry: D2.

## D. Shape, re-decided
Each is a fresh verdict by the tests in notes/api-design.md, including those that stay.

Change:
1. **`Config` as one struct for every constructor** → required inputs become arguments. `hosts` is read only by `create`, `restore` and `pair`; `store` is ignored by every `attach*`; `remotes` by most. `Osis::create(Store, hosts, Config)`, `open(Store, Config)`, and so on; `Config` holds only what applies everywhere, with `Default`. `clock` and `seed` move to `internals`.
2. **`attach`, `attach_client`, `attach_remotes`, `attach_node`** → `Osis::connect_socket(path, Config)` and `Osis::connect(&[NodeLogin], Config)`, plus `db.attach_node` and `detach_node` for a handle with a store. `is_attached` is misnamed: it is false on a handle with `attach_node` attachments (verified). Rename it `has_store`, inverted.
7. Done with sharing (`SyncFirst`).
8. **`CommitQuery`**: builder and public fields are two ways, and `next` changes the contract ("needs a scope", "not with `after`", new failure). Plain struct with `Default`, like the other options. `next` becomes `undo_target(&scope)` and `redo_target(&scope)`; `Next` goes. `actor(a)` adds to `actors`: one spelling.
10. **`GroupPolicy`**: a whole-replacement struct with `publish_reach: Option<bool>`. `None` is a third state, so make it `Reach::{Auto, Always, Never}`. Getter and setter have unrelated names (`group_policy`, `sync_policy`): `sync_options` and `set_sync_options`. `receipts_only` → `SyncMode::{Full, HeadersOnly}`.
11. **`Hosting.policy: BTreeMap<String, u64>`** → a typed struct; unknown names then cannot exist at run time. `listen: Vec<String>`, `client_listen(&[String])` and `relays` → a URL type, or at least consistent with `Address`.
12. **`Diagnostic { kind, tids, commit, peer, detail }`**: the meaning of `tids` depends on `kind` (documented positionally: "`tids`: item, group") → an enum with named fields per kind.
13. **`Stamp` and `CommitInfo`**: verified the same fields but for `Option<CommitId>` vs `ChangeId`, and only `Stamp` has `shown()`. One type.
14. **`SyncScope::Group(t)`** takes any thing → `SyncScope::{All, Thing(t)}`, matching `Scope`.
15. **Waiting**: `wait_synced` takes a timeout, `redeem` and others use `Config.wait_timeout`, demotions use constant `PRESYNC_WAIT` or `Try(d)`. Every `async` call takes one explicit timeout, and the constant and config field go. Check the attach dial, which needs a value too.
17. **Callback naming**: `watch_*` take a callback under another word. All callbacks are `on_*`: `on_thing_change`, `on_grants_change` (done), `on_status_change`, `on_change`, `on_history`, `on_diagnostic`. All return `Result<Subscription>` and all get `&Osis`; `TextSession::on_remote` currently does neither.
18. **`AspectKey`**: three implementations (`Aspect<T>`, `Ak`, `Key`) plus `db.key`. `Key` with no schema is `Ak`. One dynamic key: `db.key(name)` typed when a schema is registered, else untyped. `Ak` becomes a name only, if the examples stay readable. The trait's methods exist for generated code and the crate: seal it or hide them.
19. **`LinkOpts`, `GrantOpts` and `SetRoleOpts`** stay structs, but `..Default::default()` should work on all three; `LinkOpts` is spelled out in full in the crate docs today.
20. **`now()`** on an attached handle that cannot reach its node falls back to this process's clock, unsaid. A time is no decision-maker's default, but it should say so or return `Result`.

Added by step 2's review (agent's call):
- **`on_status_change`** gets `Result<Status>`, like the roster watch (with D17): today a store failure at a status change is told to nobody.

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
- **`osis::core`**: re-exports `KEYS`, `SECRETS`, `LABEL`, `ROLES`, `TENURES`, `REACH`, `SEEN`, `NODE`, `PLACED`, `GROUPS`, `ASPECTS`, `TID`, `group::{ITEMS, SUBGROUPS}`. Keep `NAME`, `BODY`, `TAG`, whatever else apps truly write, and the required-retention keys (`REQUIRED`, `Required`, `RequiredRules`: no typed calls, one rule for all of it).
- **`pub use osis_schema as schema`** exports the whole crate for generated code. Give generated code a narrow doc-hidden path.
- **`CreationRecord`, `Cause`, `EphemeralId`, `CommitId` beside `ChangeId`, `LabelId`**:
  - One opaque `ChangeId`.
  - `Source::Derived(Cause)` has `LateDelta`, `Validity` and so on: keep `Derived` with a small plain reason, or none.
- **`Ts`** is a hybrid clock value, exposed in `Stamp`, `CommitInfo`, `Committed` and `CommitQuery.since` next to `WallMs`. One `Time` type for apps; ordering is opaque in `HistoryPos`.
- **`CommitKind::{Role, Snapshot}`**, `HistoryBody::Dropped`, `CommitEntry.dropped`: "snapshot" is compaction. Keep what an app must see to explain history (notes/api.md Attribution), and rename it in plain words.
- **Sync status**: `GroupSync.labels`, `not_admitted`, `Stranded`, `ReceiptsOnly`, `NoRoute`, `unrouted`, `Status.split`. Labels are needed to configure hosts, so call them what they are for hosts (`host_ids`?) and keep them with hosting.
- **Other words to translate or hide**: `rotate_reach`, `publish_reach`, `rotate_client_key`, `materialize_limit`, "pre-sync", "co-reader", "K", "L".
- **`Key::new(ak, schema)`** and `Schema` in the public API (`register_schema` takes a source now): see D18.
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
| `path.len()` | `byte_len()` | It is canonical size in bytes, not element count |
| person, "person actor", `Person`, `PERSON` | account | Decided: issues/account-rename.md |
| `sync_now` | `nudge_sync`? | It nudges; `wait_synced` is what syncs |
| `make_link`, `redeem`, `import_contact` | keep | Clear |
| `hosts()`, `hosting()`, `host_address()` | `hosts()` and `own_host_*` | The hosts this account uses vs the host this node runs |
| `placed.0~`, `PlacementNotPersisted`, `place_plan`, "placed" in prose | membership words | Decided 3 |

### Vocabulary
- **Nodes** (Tess; spec/requirements.md Terms, issues/node-host-unify.md): `node` in the API, never `device`: `devices()` and `remove_device` become `nodes()` and `remove_node`; apps may say device to their users. Host is a role. "Blind node" goes. "Thin client" and "Owner" go: a **client** is a program using a node out of process, local or remote, and a **remote client** one on another machine; neither name says what actor it acts as. `is_attached` and `attach*` follow (D2).
- **Host, not relay**: unless Tess decides otherwise. Relay already means forwarding without storing (iroh relays, relay-only commits).
- **Account**, not person or user: an account may be a team, a bot or a shared identity. `me()` keeps its name.
- **Roles**: one sentence for all of it: an actor is *granted a role* on a thing, and is then a *holder* of that role. A role can be set, or removed. Clean out older words wherever API, CLI, spec and notes use them:
  - *edge* for a grant (comments in `core/osis/src`, 131 lines in `spec/`), including "tied edge" and `EdgeKey`. The API and CLI say grant.
  - *rights* where a role is meant, *demotion* and *revocation* for setting or removing a role (55 and more lines). `Error::Permission` may stay as the general word, or become `NeedsRole`.
  - *entitlement* and *tenure*: internal, keep them out of anything public; the spec may keep what it must define.
  - *share*: dropped from the API but for `ShareLink`, which step 6 may rename.
- **Membership**: being in a group grants nothing (spec/permissions.md §1 already says so) and a thing can be in many groups. The docs must keep "a group's members" (what it contains) clearly apart from "a group's holders" (who has a role on it), since people will confuse them. Sync's other "placed" (a commit held at a host, spec/sync.md §5) becomes "uploaded" or "at a host".

## G. From building osis-chat (old api-review, not re-checked)
- No `at.history_entry(id)`: a lookup is a walk from `After(HistoryPos::time(ts))`, so an id must carry its `ts` and aspect.
- `on_history` is per aspect, so a per-year chat holds one subscription per year, none for a year beyond next.
- `HistoryBody::Purged { by }` once needed a commit query with no by-id filter; check it's solved by `actor`.

## H. Docs
- Crate docs after the refactor: rewrite `lib.rs` sections to the Public docs rules in notes/api-design.md, since most examples change anyway. "Footguns closed" is the first to go or become plain advice. Module-level jargon in the first lines of each section ("placement is a group op") likewise.
- Rendered docs still cite `spec/` as plain text (about 90 lines, 38 in `share.rs`). Keep those that help a reader, drop the rest. To make them links, a doc-only module could embed the spec with `#[doc = include_str!(..)]`; not tried. Links between spec files would need rewriting, and `tools/gate.sh` runs its full gate on spec edits once Rust reads `spec/`, unless that file joins its docs step.

### Follow-ups from Sharing
- `remove_device` stays as `set_role(me, node, None, ..)` for what it returns (working links). If apps find it no help, drop it: two lines at the caller.
- `Holder` has no `invite` or tie: `grants` one level down covers them. Chat still walks `grants` for participants and tells a person from a team by `owner_of`; owner removal must give it another test (the same in the app's `reach`).

## Related issues, resolve within this work
- issues/api-leaving-give-up.md (a give-up call belongs with `leave`), issues/account-rename.md, issues/grant-rename-multi-actor.md (public `act_as(actor) -> Osis` could replace `Write::act_as`).
- issues/api-deferred.md stays for what isn't built, but its shapes should follow this design.

## Execution
One branch per step, in order; each merges before the next starts.
- **4. Shapes**: D. 4a (writing and addressing data) done; 4b: D1, D2, D8, D10 to D15, D17 to D20.
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
