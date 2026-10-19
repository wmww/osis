# Rust API
> Summary: The designed shape of the `osis` crate (the only crate apps use): a synchronous local data API (typed aspect keys, `get`/`at`, RAII watches, a `Write` batch with `set`/`edit`/`replace`/`remove` and path ops, explicit owner and placement, rights checked locally, bounded materialization), signals, undo, text sessions, minimal queries, the sharing and sync surface (async only where another node is waited on), diagnostics; the owner's fixed directions; the footguns the shape closes and why; rejected shapes. Shape is the plan's target, to be refined with the example apps (owner left it open).

## Fixed directions (owner)
- Plain values and listeners, no CRDT concepts (notes/crdt.md). A lost concurrent write looks like any LWW loss.
- Large values: getting a string as one `String` is allowed; there must also be tools to read, edit and listen to a large value without materializing it.
- Undo: per actor by default; plus a view of all available changes in scope from which an admin may remove others' (notes/crdt.md).
- Listeners fire for local changes too: a committed write fires matching aspect listeners and a sent signal fires matching signal listeners on the same node, including those of the app and handle that made the change.

## Design rules
- **Local and synchronous.** Every data operation completes against the local store with nobody online (spec/requirements.md, Offline), so reads, writes, watches, undo, sending signals and membership writes are plain synchronous calls. Only operations that wait for another node are `async`: redeem a link, pair a device, restore from a card, a demotion's pre-sync, "wait until synced". Those futures are runtime-agnostic (resolved by a channel from the handle's own background runtime, which is tokio by default or a `Handle` the app passes). A browser build later gets the same sync API over a worker-backed store; nothing in the shape assumes blocking is impossible.
- **Explicit where a wrong default is silent**: the owner of a new thing, its sync placement, the materialization bound, waiting for the pre-sync before a demotion.
- **One `Error` enum** with stable categories; an absent aspect or unknown tid reads as `None`, never as an error.
- **No callback under a lock.** Callbacks run on one dispatcher thread per database, in commit order, after the commit is durable; any API call is allowed inside a callback.
- Nothing about CRDT internals, labels, blobs, epochs, keys or servers' innards reaches the API except in diagnostics and sync status. Vocabulary: thing, aspect, group, actor, member, role, device, server.
- Every tid that enters or leaves the API is resolved through moves (below).

## Handle and lifecycle
- `Osis: Clone + Send + Sync`; clones share one database, which closes with the last handle (`close()` flushes; drop is fine). One person per database; a second person is a second store directory.
- `Osis::create(Config, NewPerson) -> (Osis, RecoveryCard)`: new node, new person actor (recovery key owns it, this node is its admin), home group synced to `Config.servers`. The recovery seed exists only in the returned card; the app shows or stores it, osis keeps none of it.
- `Osis::open(Config) -> Osis` (existing store); `async Osis::restore(Config, &RecoveryCard)`; `async Osis::pair(Config, &PairOffer)` (new device, offer made on an existing one).
- `Config { store: Memory | Dir(PathBuf), runtime: Option<tokio Handle>, servers: Vec<ServerAddr>, materialize_limit: usize (default 64 MiB), idle_commit: Duration (text sessions, default 2 s) }`. `servers` seeds `create`, `restore` and `pair`; an opened database keeps its stored list (`add_server`).
- Identity: `node() -> Tid` (this device), `me() -> Tid` (the person actor). Apps pass `me()` or a team/folder actor as the owner of what they create.

## Keys: typed aspects and signals
- `trait AspectKey { type T; fn ak(&self) -> &Ak; fn schema(&self) -> Option<(SchemaId, u32)>; fn decode(&Value) -> Result<T, PathError>; fn encode(&T) -> Value; fn defaults(&self) -> AspectDefaults }` (retention, expiry). Defined in osis-schema, re-exported.
- Untyped: `Ak` is an `AspectKey` with `T = Value` and no schema (writes go out untyped: no schema index, core default retention). Typed: constants generated from a `.osis` file (`notes::BODY: Aspect<Markdown>`, `notes::TASKS: Aspect<Vec<Task>>`) carrying AK, (schema ID, revision), defaults and codec. A read through a typed key cannot be mistyped; a write through one is validated against the writer's schema (every declared field required, spec/versioning.md §5) and carries its schema index.
- `Signal<T>` keys likewise for declared signal kinds. Core aspects as typed constants in `osis::core` (`GROUP`, `MEMBERS`, `CREATED`, `MOVED`, `WAS`, ...).
- Typed reads map `string`/`markdown`/`text` to `String`, `blob` to `Vec<u8>`, `tid` to `Tid`, `timestamp`/`duration` to osis time types; records to generated structs and enums with `TryFrom<Value>`/`Into<Value>`.

## Reads
- `db.get(tid, key) -> Result<Option<T>>`; `db.at(tid, key) -> AspectRef<T>` with `.get()`, `.path(p).get::<U>()` / `.get_value()` (per-path typed or untyped read, so one bad element of a large collection is skippable), `.len()` (canonical size), `.stream() -> impl Read + Seek` (large string or blob), `.watch()`, `.on_change(f)`.
- `db.read(|r| ...)`: a consistent view across several reads (the engine's read lock, no store-level snapshot needed). `db.aspects(tid) -> Vec<Ak>`, `db.groups_of(tid) -> Vec<Tid>`, `db.roster(actor) -> Roster` (the timeline's roster, spec/permissions.md §2), `db.role_on(tid) -> Option<Role>` (this node's effective role; UIs grey out what it cannot do).
- Typed failure: `Error::Type { path, reason }` (unknown case, mismatch, missing required field). Untyped reads never fail on typed grounds.
- **Materialization bound**: a value whose canonical size exceeds `materialize_limit` returns `Error::TooLarge { len }` from `get` and from any typed read; read it by `stream()` or by path (a path read into a huge map or list costs O(entry) and never loads the whole). Explicit failure beats an out-of-memory.
- Values are snapshots: plain `Value` or generated structs, nothing reactive hidden inside.
- `Path`: steps `Field(id) | Case(id) | Key(Value) | Index(usize) | Elem(Value)`; `p![..]` builds one from literals and generated field/case constants (`task::DONE`). Typed path builders from codegen are optional (plans/schema.md).

## Watching
- `db.at(tid, key).watch() -> Watch<T>`: taken atomically with the current value, so no change is missed between read and subscribe. `current() -> Result<Option<T>>`, `async changed()`, `changed_timeout(d)`, `on_change(f) -> Subscription`.
- `db.at(tid, key).on_change(|c: Change<T>|) -> Subscription` = watch plus callback: the callback runs once with the current value (`Origin::Initial`) through the dispatcher like every later call, then on every change. `db.watch_thing(tid)` for all aspects of a thing (`Change<Value>` names the AK). `db.watch_roster(actor)`, `db.watch_status()`.
- `Change<T> { ak, value: Result<Option<T>>, source: Source }` with `Source::Initial | Local(CommitInfo) | Remote(CommitInfo)` and `CommitInfo { id, actor, node, ts, received }`. Display time for feeds is `min(ts, received)` (a sender's skewed clock).
- `Subscription` is RAII: dropping it unsubscribes; `detach()` keeps it for the database's life. No ids to remember.
- Coalescing: a watch holds only the latest value; a callback that falls behind sees every commit's effect but not necessarily one call per commit. A slow callback delays later callbacks, never writes or sync. A watch on a value above the bound delivers `Err(TooLarge)` per change and the app re-reads by stream or path.

## Writes
```
let mut w = db.write();
let note = w.create(db.me(), Place::In(folder))?;
w.at(note, notes::TITLE).set(&title)?;                       // make equal: structural diff against current state
w.at(note, notes::TASKS).edit(&shown, &edited)?;             // apply only what the user changed since `shown`
w.at(note, notes::TASKS).path(p![2, task::DONE]).set(&true)?; // path op
w.at(note, notes::BODY).replace(&body)?;                     // reset, then the value
w.at(note, notes::VIEWS).inc(1)?;
w.at(msg, chat::BODY).expires_in(DAY).set(&text)?;           // retention and expiry per aspect write
w.at(note, key).remove()?;
w.place(note, other_group)?; w.unplace(note, folder)?; w.add_subgroup(g, sub)?; w.delete(note)?;
let done: Committed = w.commit()?;
```
- Whole-value ops: `set(&v)` makes the aspect read `v` (the spec's structural diff against the current state, spec/crdt.md §9: concurrent edits inside the value survive, but a field the app did not touch is written back if it differs from the current state); `edit(&base, &new)` writes only the difference between what the app showed and what the user produced, as path ops against the current state (struct fields, enum case, map keys, set elements, bag values exactly; sequence edits rebased onto the current sequence by matching `base` to it, notes/crdt.md Implementation), so a remote change to another field during editing is never overwritten; `replace(&v)` resets then writes; `remove()`. `edit` or path ops are the rule for anything a user edits while remote changes may arrive; `set` is for "the value must be exactly this" (imports, derived data).
- Path ops at `.path(p)`: `set`, `replace`, `remove`, `set_case(id, payload)`; list `insert(i, items)`, `delete(range)`, `move(range, to)`; text `splice(range, str)`, `undelete(range)`; set `add(v)`, `remove_elem(v)`; map `put(k, v)`, `remove_key(k)`; bags `inc(n)`, `observe(v)`. Index paths resolve against local state at commit time.
- `create(owner, Place) -> Tid`: owner explicit and fixed forever; needs write on `owner` (checked locally). `Place::In(group)`, `Place::InAll(&[Tid])`, `Place::Unsynced` (device-local, or a group that will be synced itself). A thing placed into a group whose closure has no synced group gets a `NotSynced` diagnostic after commit (spec/requirements.md, Offline and network).
- `delete(tid)`: removes every aspect the node knows and every known placement. Tids never die and a later write recreates the thing; no wire concept.
- Rights are checked locally before signing: `Error::Permission { tid, needs: Role }` when the acting actor lacks write (admin for membership-class aspects) on a touched thing; `Error::UnknownThing` when its `/created` is not held. A write is never emitted to be un-merged elsewhere.
- `commit()` is one atomic commit over every touched thing, any owners and reader sets, of any size (deltas page, spec/crdt.md §8). Returns `Committed { commit, ts }`. Own watches fire after the commit is durable.
- `Write` is `#[must_use]`; dropped uncommitted it discards its ops (debug log). `db.write_with(|w| ...)` commits on `Ok`. Reads inside a `Write` see committed state only; pending ops are invisible until commit.
- The node always acts through `me()`; acting as another actor (anonymous writing, notes/permissions.md) is a later `Write::acting_as`.
- Retention and expiry per aspect write: `.expires_at(T)` / `.expires_in(d)` / `.retention(Retention)` on `AspectWrite`, defaults from the key; validated at the op (`Error::Invalid`).
- Membership-class aspects (`/members`, `/keys`, `/secrets`, `/label`, `/tenures`, `/moved`, `/was`) are written only through the sharing and sync calls below; a `Write` op on them fails with `Error::Invalid`. `/group` is ordinary (`place` and friends are path ops on it).

## Text editing sessions
- `db.edit_text(tid, key, path) -> TextSession`: a buffer the UI edits (`text()`, `insert(at, s)`, `delete(range)`, `replace(range, s)`, `cut(range)`, `paste(at)` with remembered ranges so a paste is a move plus undelete when the clipboard still matches, notes/crdt.md); remote edits are merged into the buffer and reported through `on_remote(|edits|)` so the UI can map cursors; commits on `commit()`, after `idle_commit` of inactivity, and on drop. This owns the "one commit per editing pause, never per keystroke" rule (spec/requirements.md, Generality); apps never commit per keystroke by accident because the session is the only path that makes keystroke-granular changes convenient.

## Signals
- `db.send_signal(tid, key, &value, Target::All | Target::Node(tid)) -> Result<()>`: needs write on the thing; never stored; local listeners fire; connected nodes receive best effort (notes/ephemeral.md).
- `db.on_signal(tid, key, |s: SignalEvent<T>|) -> Subscription`; `SignalEvent { value, actor, node, ts }`. Event-style signals should carry a sender sequence in their value (a node on several relays may see one twice).

## Undo
- `UndoScope::{Thing(tid), Aspects(Vec<(Tid, Ak)>), Group(tid)}` (a document, a form, a folder). `db.undo(&scope) -> Result<Option<Committed>>` and `redo` operate on this actor's own changes in scope (derived from its commits, so it works across devices); `None` when nothing is undoable.
- `db.history(&scope, HistoryQuery { limit, before }) -> Vec<HistoryEntry { commit, actor, node, ts, aspects, state: Undoable | Undone | Dropped(reason) }>` lists everyone's changes; `db.undo_commit(id)` undoes any entry the node may write (an admin reverting others). A register undo whose previous body was compacted away is `Dropped(Compacted)`, never a silent no-op (spec/crdt.md §4.6).

## Large values
- Typed and untyped reads materialize up to `materialize_limit`; above it `stream()` (`Read + Seek`, lazily fetching chunks, memory bounded to a chunk plus the tree path), `len()`, and path reads. Writes: `set_stream(impl Read)` on a `blob`/`string` position builds the chunk tree without materializing (plans/large-values.md); `set`/`edit` accept in-memory values of any size the caller has. Equality is by content; links never appear in values the API returns (`Value::Link` is replaced by the materialized value or the read fails `TooLarge`).

## Queries (minimal in the MVP; a design pass later)
Per-aspect reads are not enough for any list-like UI. Expect most of a slow, not very feature-rich database to grow over the local store, over time; nothing of it touches the wire. MVP shape, enough for the example apps:
- `db.query(Query::in_group(g).with(key).order(Order::Time | Order::Field(path)).page(n)) -> Live<Vec<Hit<T>>>`, things in the group (transitive) carrying the aspect, paged, with `Hit { tid, value: Result<Option<T>>, ts, received }` and a watch on the result for changes in the visible range (a chat timeline, a feed, an inbox).
- `db.backlinks(tid) -> Live<Vec<(Tid, Ak)>>`: things whose values reference the tid, resolved through moves.
- Later: filters over values (unread, by actor, by tag) and counts, live; text search. Indexes are local, rebuildable, sharded per aspect (notes/local-store.md).

## Sharing and membership
Synchronous unless noted; each is one membership commit made locally (spec/permissions.md §2), delivered by the sync layer.
- `db.grant(target, member, role, Edge { until, invite })`: needs the member's `/keys` held (contact card, a shared group, pairing), else `Error::UnknownActor`. The first non-owner member of a plain thing gives it secrets of its own (about 2.6 KB of boxes per member: share sets through one actor, notes/permissions.md Patterns).
- `db.change_edge(target, member, Edge)` for `until`/`invite` or a higher role. `async db.demote(target, member, Role | Remove, Demotion { sync: WaitForSync::Required | Try(timeout) | Skip, backdate: Option<Timestamp> })` for anything lowering a role: the pre-sync (below) runs first; `Required` fails with `Error::Unsynced { groups }` when a group cannot be synced, `Try` proceeds after the timeout with a diagnostic, `Skip` stamps now (stolen device). `db.leave(target)` is a self-removal.
- Devices: `db.pair_offer() -> Pairing { offer: PairOffer, async done() -> Result<Tid> }` (the offer is short-lived, shown as text or QR, and carries this device's reach info; the new device runs `Osis::pair`, which connects directly to this one; `done` resolves with the new node's tid); `db.devices() -> Vec<Device>`; `async db.remove_device(node, Demotion)`.
- Links: `db.make_link(target, role, LinkOpts { until, single_use }) -> Link` (URL or bytes); `async db.redeem(link) -> Tid`; `db.links(target)`; `async db.revoke_link(id, Demotion)` (its joiners stay only if re-granted directly; a bearer may have kept the seed, spec/permissions.md §9). Bearer read (`async Osis::open_link(Config, link)`, read-only, no account) may slip from the MVP.
- Contact cards: `db.contact_card() -> Card`; `db.import_contact(&Card) -> Tid` (the person actor, then usable in `grant`).
- Moving: `db.move_thing(tid, new_owner, Place) -> Tid` (copy with imported history, `/was`; `/moved` on the old thing when this node may write it). `db.same_thing(a, b)` is the only explicit resolution call.

## Sync configuration and status
- `ServerAddr` = transport URL plus the server's key (`FromStr`/`Display`); `db.servers()`, `add_server`, `remove_server`.
- `db.sync(group, &[ServerAddr])` makes a group synced (its own label; admin of the group); `db.unsync(group)`; `db.sync_policy(group, GroupPolicy { publish_reach, heartbeats })` (exclude `/reach` under open audiences, notes/networking.md). The person's home group is synced at `create`.
- `db.status() -> Status { connectivity, groups: map<Tid, GroupSync { state: Synced | Syncing | Unreachable | Stranded | NoServers, pending_uploads, last_sync }> }`, `watch_status()`. `Stranded` means this device waits for a re-seal (spec/permissions.md §3).
- `async db.wait_synced(scope: Group(tid) | All, timeout)`: resolves once every local commit in scope is at a server and a pass changed nothing; `db.sync_now()` nudges. CLI and tests use these; apps mostly watch status.
- Bundles: `db.export_bundle(&[groups], impl Write)`, `db.import_bundle(impl Read)`. P2P and LAN need no configuration.

## Diagnostics (decided; shape is proposal)
A place to dump problems such as a colliding record from a peer, a move with several claimants, rejected writes from a revoked actor, a thing created into an unsynced group, a demotion that proceeded without its pre-sync. Apps may log, surface or ignore it; correctness never depends on anyone seeing it.
- `db.on_diagnostic(|d: Diagnostic|) -> Subscription`; structured (kind, tids, peer, time). Default sink is the log.
- A peer must not be able to flood it: dedupe per (kind, tid), rate-limit per peer.
- Must include: "this device was removed from actor X by node N at time T" (a stolen device's backdated removal otherwise looks like a silent lockout; the recovery card is the remedy) and "stranded on group G" (also in status).

## Errors
`Error::{UnknownThing{tid}, UnknownActor{tid}, Permission{tid, needs}, Type{path, reason}, TooLarge{len}, Unsynced{groups}, Invalid(reason) (a malformed link, card or value), Storage(..), Network(..), Closed}`. Peer-caused problems never surface as errors to the app; they are diagnostics.

## Typed reads (decided; spec/versioning.md §5)
Typed reads fail with an error carrying the path on an unknown enum case, a type mismatch or a missing required field; per-path reads let an app skip one bad element. The untyped `Value` API always works. App types are views over the wire type, generated or hand-written; transitions and the form-choice policy are codegen conventions (notes/versioning.md). Codegen warns on `list<struct>` aspects (records edited concurrently belong in `map<K, struct>` or get path ops: the list diff pairs changed entries in order and a misaligned pair loses concurrent edits).

## Tids and moves (spec/permissions.md §7)
A thing never changes tid or owner; moving it makes a copy with a new tid (`/was` on the copy, `/moved` on the old thing if its owner cooperates).
- Every call that takes a tid resolves moves internally by the §7 rule; watches registered under an old tid keep firing. Roster reads resolve `/members` keys too.
- Values returned have known old tids replaced by the resolved one (typed tids and `osis://` links in markdown), so tids read from osis compare equal. Resolution is a read-time view: stored bytes are untouched, and `set`/`edit` diff against the resolved view, so writing a value back never rewrites references. An app pins a reference by writing it explicitly.
- `same_thing(a, b)` only for identity of a tid the app kept (memory, config, URL) against one read later; `Tid` equality is plain bits.
- Attribution shown for imported writes is the origin commit's author and `ts`.

## Demotion and the pre-sync (decided)
A demotion's frontier is the demoting node's own receipts (notes/permissions.md, Revocation), so osis syncs every group below before stamping it (spec/permissions.md §5.3); in the common case there is no tradeoff. The sync fails when a group is unreachable, the node is stranded on it, the tree is too big for the device, or the app will not wait (a hostile member or lost device: reverting their unseen work is then wanted). The app chooses by `Demotion.sync`; a UI may route the choice to a user, osis never requires a human. Partial sync is partial protection (the frontier is per aspect). Organizations demote from a node that tracks the tree (an admin node holding the company actor's secrets). Rejected: a "cut access only" removal (`until` = now by an admin) leaves a permanent backdating window until a real demotion follows; third-party receipts fail the fixpoint model.

## Footguns closed (keep them closed)
- Read-modify-write clobber (a form saved with `set` wipes a tag another device added meanwhile): `edit(base, new)` and path ops; docs steer every interactive edit there.
- Out of memory on an unexpectedly large value: the materialization bound fails explicitly; streaming and path reads exist.
- A thing that never syncs: owner and placement explicit at creation, `NotSynced` diagnostic.
- A thing owned by the device (never shareable): owner is always passed; `me()` is the common answer.
- A forgotten unsubscribe: RAII `Subscription`.
- Missed change between read and subscribe, and a callback invoked on the registering thread once and the dispatcher thread later: atomic `watch`, initial call through the dispatcher.
- Writes a node is not allowed to make, emitted and un-merged elsewhere later: rights checked locally at commit.
- `async` reads forcing a runtime into GUI apps and hiding that nothing waits: synchronous data API.
- Per-keystroke commits (13 bytes forever each): the text session.
- Demotion stamped without syncing what the member wrote: `WaitForSync::Required` is the default; skipping is spelled out.
- Tid comparison across moves: resolution inside every call and in returned values; one explicit `same_thing`.
- Concurrently edited records in a `list<struct>`: codegen warning, path ops.
- Deadlock or reentrancy inside callbacks: no callback under a lock, any API usable from a callback.
- Secrets in the API: none; the recovery seed only in the card at creation, the link seed only in the link.

## Rejected shapes
- Everything `async` (the earlier sketch): local operations never wait, and every GUI would carry a runtime; browsers are served later by a worker-backed synchronous store.
- `ListenerId` cancellation and a callback invoked before `listen` returns.
- An entity/ORM layer typing whole things: aspects belong to different schemas and apps; per-aspect typed keys fit the model.
- Auto-subscribing reactive reads (reads inside a computation register listeners): hidden magic; `Watch` covers it explicitly.
- `set` diffing against the app's last read implicitly (state hidden in the handle): `edit` takes the base explicitly.
- Exposing links or a `Value::Large` variant in untyped values: the bound plus `stream()` keeps values plain.
- A default owner (`me()`) or default placement.

## Open
- The query design pass (which filters and indexes, live counts, text search).
- Typed path builders from codegen; a serde layer `Value <-> app types` as a convenience.
- Bearer read and anonymous-writing conveniences may slip from the MVP (notes/overview.md, MVP scope).
- Browser build: the sync API over a worker-backed store (SharedArrayBuffer + Atomics.wait), not in the MVP.

## Implementation (first half: plans/api.md steps 1–2)
Module map (`crates/osis/src`): `handle` (`Osis`, `Config`, `StoreAt`, `MemStore`, schema registration, `engine()` escape hatch), `read` (`Reader`, `AspectRef`, `PathRef`, materialization, watch registration), `write` (`Write`, `AspectWrite`, `PathWrite`, `Place`), `watch` (dispatcher, `Subscription`, `Watch`, `Change`), `undo`, `signal`, `keys` (`Key`, `SignalKey`, `core`), `share` (second-half stubs, `move_thing`), `error`.
- **Dispatcher**: one engine mutex; every call drains the engine's event channel into the dispatcher queue under that lock, numbering messages, so the queue is in commit order. A subscription ignores messages numbered before it registered; its initial values are read under the same lock, so `watch`/`on_change` are atomic with no duplicate. Callbacks read the latest state when they run and skip a value equal to the last one delivered (coalescing). The dispatcher holds a `Weak` to the database; the last handle closes it. `settle()` waits until everything queued so far is dispatched (tests and scripts wait without sleeping; no-op on the dispatcher thread).
- **Identity**: until membership flows land, `create` makes a person actor owned by the node and a home group owned by the person (plain `/group`, no label); both tids live in node `app_record`s. No `RecoveryCard` yet; `create` returns `Osis`.
- **Writes** act as `me()` by default (`act_as` to change). `commit` returns `Option<Committed>` (`None`: nothing changed). Rights and unknown things are the engine's check before signing (`Permission.needs` is `Write`: membership-class AKs are refused by the API with `Invalid` before that). `make_group` gives a thing an empty `/group`. `purge()` = purge the aspect's history plus `remove`. Path `remove` works on a map entry, set element or list element. `edit` = `osis_crdt::diff_values(base, new)` under the key's schema view, pushed as path ops.
- **Reads**: `get`/`at` take keys by value. Large values are materialized with a budget through `Engine::read_large_max`; past the bound `TooLarge { limit }` (the length is unknown without reading: tree nodes carry none, issues/large-value-seek.md). Typed path reads materialize only the position; an absent struct field reads as its default by projecting its parent.
- **Keys**: `Key` (AK plus an optional run-time schema; `Osis::key` picks the registered schema declaring the AK, the core schema for core AKs) serves the CLI and tools. `SignalKey` is implemented for `Signal<T>` and `Ak`.
- **Undo**: stacks are derived in `osis` from `Engine::changes`: a commit is in effect unless an undo of it in effect exists; even undo depth = a change, odd = an undo. `undo`/`redo` take this actor's newest in-effect entry whose undo writes something. Chained undo of one register stops after one step (issues/undo-chain-register.md). `history` states: `Undone`, `Dropped(Compacted)` (a touched body in scope not held), else `Undoable`.
- **Signals** reach local listeners only (node-sync delivers remotely; its `Event::Signal` lacks the target tid yet).
- **Not yet** (plans/api.md steps 3–4): `stream`, `len`, `set_stream`, text sessions, queries, backlinks, `undelete` (the crdt has undelete only inside paste), `NotSynced` diagnostics (no sync state), `watch_status`, remote signals, `Config.runtime`/`servers`/`idle_commit`; sharing, devices, links, cards, servers, sync and status are stubs returning `Error::Unsupported`. `move_thing` works but does not re-grant the old roster. Untyped list/text sequence ops fail (the crdt needs a typed position for `Insert`/`Delete`/`Move`).
- **Tests**: crates/osis/tests (`api`, `watch`, `history`), memory store, `ManualClock`, seeded rng; the two-node remote watch delivers packages engine to engine as `LocalPeer` does. Doc examples per concept in lib.rs (compiled), plus `compile_fail` checks for the must-use lints.
