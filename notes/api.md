# Rust API
> Summary: Fixed API directions (plain values and listeners, no CRDT concepts, large values materialized and streamed, move resolution inside every call, typed-read failures, diagnostics channel) plus an early sketch of the `Osis` handle and its functions. The API is NOT decided: shape it during implementation and refactor as example apps show what works (owner).

## Fixed directions (owner)
- Plain values and listeners, no CRDT concepts (notes/crdt.md).
- Large values: getting a string as one `String` is allowed; there must also be tools to read, edit and listen to a large value without materializing it.
- Undo: per actor by default; plus a view of all available changes in scope from which an admin may remove others' (notes/crdt.md).
- Listeners fire for local changes too: a committed write fires matching aspect listeners and a sent signal fires matching signal listeners on the same node, including those of the app and handle that made the change.

## Sketch (starting point, not a decision)
`Osis`: a cloneable, thread-safe handle to an internal `Database` (aspect map, sync engine, store); many handles per database, which drops with the last handle. Listeners are invoked once before the listen call returns (not for signals) and return a `ListenerId` for cancellation.
- `async Osis::get_aspect(&self, tid, ak) -> Result<Value>`
- `Osis::text_search(&self, aspect: Option<&Ak>, query: &[&str]) -> AsyncIter<(Tid, Ak, Value)>`
- `Osis::mutate(&self) -> Mutator`
- `async Osis::listen_aspect(&self, tid, ak, callback: async value -> ()) -> Result<ListenerId>`
- `async Osis::listen_aspect_mut(&self, tid, ak, callback: async (value, mutator) -> ()) -> Result<ListenerId>`
- `Mutator::create_thing(&mut self, place: Placement) -> Tid`: placement is a group (or an explicit `Local`), never defaulted, since an unplaced thing silently never syncs (tension 16); a diagnostic reports things still unplaced after commit. `delete_thing` has no wire meaning (tids never die): define it as remove every known aspect plus group placements, or drop it.
- `Mutator::set_aspect(&mut self, tid, ak, value)`: structural diff by default (concurrent edits elsewhere in the value survive); an explicit replace variant resets the aspect. Path ops to add: set field, insert/remove index, add/remove key, splice text, increment (spec/crdt.md §5).
- `Mutator::remove_aspect(&mut self, tid, ak)`
- `async Mutator::commit(self) -> Result<()>`: one atomic commit for every touched thing, across owners and reader sets (spec/sync.md §3, Projection).
- `async Osis::send_signal(&self, tid, kind, value)`, `async Osis::listen_signals(&self, tid, kind, callback)`: never stored, reach local listeners plus connected nodes only (notes/ephemeral.md).
- An editing-session API for text (a buffer that commits on pause or blur), so apps do not commit per keystroke (tension 14: about 13 bytes per commit forever).
- Codegen: a `list<struct>` aspect gets a warning and path ops; records that are edited concurrently belong in `map<K, struct>` (the list diff pairs changed entries in order and a misaligned pair loses concurrent edits).
- Undo of a register write made on another device is a silent no-op where the previous body was compacted away (spec/crdt.md §4.6); the undo view should say so.

## Queries apps will want (direction, not specified)
Per-aspect reads and text search are not enough for any list-like UI. Expect to grow most of a slow, not very feature-rich database on top of the local store, over time; a dedicated design pass should shape it. Kinds of things apps need:
- Things in a group (transitively) that carry a given aspect, ordered by a field or by commit time, paged, with a listener for changes inside the visible range (a chat timeline, a feed, an inbox).
- Backlinks: things whose values reference a given tid, resolved through moves.
- Filters over aspect values (unread, by author actor, by tag) and counts, live.
- Ordering by commit time should tolerate a sender's skewed clock, e.g. display time = min(`ts`, local receipt time).
- Local-only indexes that are rebuildable and shardable per aspect, since the local store erases by key (notes/local-store.md).
None of this touches the wire.

## Typed reads (decided; spec/versioning.md §5)
Typed reads fail with an error carrying the path on an unknown enum case, a type mismatch or a missing required field; they are also available per path so an app can skip one bad element of a large collection. The untyped `Value` API always works. App types are views over the wire type, generated or hand-written in the app; transitions and the form-choice policy are codegen conventions (notes/versioning.md).

## Tids and moves (spec/permissions.md §7)
A thing never changes tid or owner. Moving it to another owner makes a copy with a new tid; the copy says what it continues (`/was`) and the old thing, if its owner cooperates, what it continued as (`/moved`).
- Every call that takes a tid resolves moves internally by the §7 rule; listeners registered under an old tid keep firing. Apps never resolve in order to access. Roster reads resolve `/members` keys too, since a moved actor may be listed under its old tid.
- Values returned to apps have known old tids replaced by the resolved one (typed tids and `osis://` links in markdown), so tids read from osis compare equal. Resolution is a read-time view: stored bytes and hashes are untouched, and `set_aspect` diffs against the resolved view, so writing a value back does not rewrite references. An app pins a reference by writing it explicitly.
- Explicit call only for identity: comparing a tid the app kept (memory, config, URL) with one read later. `Tid` equality is plain bits and cannot consult the database.
- Moving is node logic over the import commit: create the copy, import the origin's commits the node holds (dead bodies included) or its snapshots, re-grant the roster, write `/was`; the old owner writes `/moved`. Attribution shown to apps for imported writes is the origin commit's author and `ts`.

## Demotion and the pre-sync (decided; shape open)
A demotion's frontier is the demoting node's own receipts (notes/permissions.md, Revocation), so osis syncs every label below before stamping it (spec/permissions.md §5.3) and there is no tradeoff in the common case. The sync fails when a label is unreachable, the node is stranded on it, the tree is too big for the device, or the app will not wait (a hostile member or lost device: reverting their unseen work is then wanted). The app chooses: the request takes fail / proceed anyway, and may route the choice to a user through a question channel paired with diagnostics; osis never requires a human, since many apps have none. Partial sync is partial protection (the frontier is per aspect). Organizations demote from a node that tracks the tree (an admin node holding the company actor's secrets). Rejected: a "cut access only" removal (`until` = now by an admin) leaves a permanent backdating window on everything below until a real demotion follows; third-party receipts fail the fixpoint model.

## Diagnostics channel (decided; shape is proposal)
A place to dump problems such as a colliding record from a peer, a move with several claimants, or rejected writes from a revoked actor. Apps may log, surface or ignore it; correctness never depends on anyone seeing it.
- Shape: `Osis::listen_diagnostics(callback) -> ListenerId`, structured events (kind, tids involved, peer). Default sink is the log.
- A peer must not be able to flood it: dedupe per (kind, tid), rate-limit per peer.
- Must include: "this device was removed from actor X by node N at time T" (a stolen device's backdated removal otherwise looks like a silent lockout; the recovery card is the remedy) and "stranded on label L" (the node placed a stranded heartbeat and waits for a re-seal).
