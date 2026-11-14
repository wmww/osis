# Listener design
> Summary: The listener model and the one `Commit` type, as built: every read that changes has one listener at its address (values: `on_change`; a value aspect's or a scope's commits: `writes`/`on_write`; a signal's: `fired`/`on_fire`; diagnostics; disputes); `Signal<T>` keys make values and signals distinct at compile time; a part is listed while in the read, kept by history, or a tombstone; undo writes back only kept history, else `NotUndoable`; every listener hears local writes after a transaction ends; text sessions follow their field. Properties 1-8 at the end, which tests cite as steps. The API's current shape: notes/api.md.

Tess decided the shape (local writes, history a run-time fact, `Signal<T>`, the fire names, the undo leak). Judged against notes/api-design.md and notes/coordination.md (Design principles).

## Principle
**Every read that can change has one listener, at the same address, called when that read's answer differs, whoever caused it.** Two kinds of read:
- A **value** (has a "now"): called once with the current value, then with the value when it differs. Calls coalesce; equal values are skipped.
- A **list of commits** (no "now"): called once per commit whose listed form reads otherwise. No initial call (read a page after subscribing). Commits never coalesce.

**Values are written, signals are fired.** A value aspect has a current value and a list of the commits that wrote it; a signal has no current value (spec/requirements.md), only the commits that fired it. Same wire, distinct API words, enforced by key type. Granularity comes from the address: to hear one map entry, listen at that entry's path.

## What you can listen to
| Read | Listener | Kind |
|---|---|---|
| `db.at(t, k).get()` | `db.at(t, k).on_change(f)` (`Change<K::T>`) | value |
| `db.at(t, k).path(p).get::<U>()` | `db.at(t, k).path(p).on_change::<U>(f)` | value |
| `db.aspects(t)` + each aspect | `db.on_thing_change(t, f)` | value |
| `db.grants(t)` / `db.status()` | `db.on_grants_change(t, f)` / `db.on_status_change(f)` | value |
| `db.at(t, k).writes(&q)` (value key) | `db.at(t, k).on_write(f)` | commits |
| `db.writes(&scope, &q)` (`Scope::{Thing, Group, Aspects}`) | `db.on_write(&scope, f)` | commits |
| `db.at(t, s).fired(&q)` (signal key) | `db.at(t, s).on_fire(f)` | commits |
| diagnostics / `db.disputes()` | `db.on_diagnostic(f)` / `db.on_dispute(f)` | entries |
| a `TextSession`'s text | `session.on_merge(f)` | value (as splices) |

Every listing returns a `CommitPage` and every commit listener gets `CommitEvent`s of the one `Commit`. A listing and its listener share a word, as the act does: `write`/`writes`/`on_write`, `fire`/`fired`/`on_fire`, `get`/`on_change`.
- **A scope lists writes**: a commit is listed at a scope while it has a listed part on a value aspect in it. Signals are heard only at their key, as `on_change`/`on_thing_change` hear none. So a thing's listing ("edited 5 min ago") and its undo never step through signals, and a `Scope::Aspects` naming a signal lists nothing for it. `Scope` is what `undo`/`redo` range over: they revert writes.
- The typed aspect address and `Scope::Aspects` list by one rule: typed and untyped views of one read, as `at(t, k).get()` and `path(p![]).get::<Value>()` are.

Rejected: one `commits` listing at every address beside `on_write`/`on_fire` (a listing and its listener would not share a word, and it would mix signals into scopes); signals heard through a thing's `on_write` (blurs the distinction the key types draw).

Not adding: a "changed paths" list in `Change` (derived changes recompute a whole aspect, so it could only say "these, or maybe everything"); a map-only or top-level-only watch (the path listener works at any depth); path scope on commit listings (nothing has asked).

## The commit
One type for every commit the API shows: listed, heard, made by `w.commit()`, `revert`, `undo`, `redo`, named by `undo_target`/`redo_target`.
```rust
pub struct Commit { pub stamp: Stamp, pub kind: CommitKind, pub reverts: Option<CommitId>,
                    pub reverted_by: Vec<CommitId>, pub in_effect: bool, /* parts: private */ }
impl Commit {
    pub fn pos(&self) -> CommitPos;
    pub fn at<K: AspectKey>(&self, t: Tid, k: K) -> Option<Part<K::T>>; // None: no listed part there
    pub fn parts(&self) -> impl Iterator<Item = (Tid, &Ak, &Part<Value>)>;
}
pub struct Part<T> { pub valid: bool, pub body: Body<T>, pub edited: Option<CommitPos> }
pub enum Body<T> { Held(Option<T>), TooLarge { limit: u64 }, Purged { by: CommitId, actor: Option<Tid> }, NotFetched }
```
- **Parts**: every listed part of the commit the caller may read, on any thing, value or signal, with its value from the commit's own body (a superseded one reads as written). `Held(None)`: a removal, or not a whole value of `K::T` (a `Mismatch` diagnostic, as for any typed read; the untyped key shows it). Decoding happens in `at`, so unread parts cost no typed read. `AspectKey` covers both key kinds: reading a part is neither writing nor firing.
- **Which parts are listed**, one rule at every address: a part is listed while it is in its aspect's read, or in history (the thing's `retention^.0` setting, until the body leaves it), or a purge tombstone where it would otherwise be listed (so never past its expiry), or this node's own invalid write (kept, marked, so its user may write it again). Replaced with no history kept, expired, compacted, another node's invalid body: not listed anywhere, whatever this node still happens to hold. **A commit is listed at an address while it has a listed part there.** An aspect keeping history lists every write until its bound; one keeping none lists only commits still in its read; listing an aspect whose writes keep no history is no error. Every synced node lists the same commits (H3). Ephemeral commits list by the same rule; their kept history is in memory, as their values are. "Replaced" is revert's skip rule (spec/crdt.md §4.6): everything the part wrote is overwritten since.
- `CommitQuery { from: CommitFrom, limit: Option<usize>, actors, kinds, reverts, reverted_by, in_effect }` (plain struct, `Default`; empty filters match all). `CommitFrom::{Newest, Oldest, Before(CommitPos), After(CommitPos)}`, neither bound counting itself; `CommitPos::time(t)` a time. `CommitPage { commits, more, complete }`: `more` past `limit`, an internal cap or the read limit; `complete: false` while a sync ID carrying the address has not finished a pass here.
- `CommitEvent::{Commit { id, commit: Option<Commit> }, Reread, Ended(Error)}`: a commit as it reads when delivered (new, late, validity flip, body arriving, purged; `None`: no longer listed here). An ephemeral signal is the one commit nobody holds: its `on_fire` event carries it as it arrived, no page shows it.
- Cost (stated): a listed commit reads all its readable parts; commits touch about 1.1 things. Each changed commit looks up the listeners at its aspects, thing and groups: O(log S + matched) per commit. Group listeners are looked up through the groups of the changed thing.

## Accessor in use: chat's messages
Messages are the durable signal `chat:msg~0` (kept forever by the chat's setting). The UI still says "send"; the code fires.
```rust
fn entry_of(c: Tid, k: &Commit) -> Option<Entry> {
    let part = k.at(c, schema::MSG)?;
    let (body, replaces) = match part.body { osis::Body::Held(v) => /* decode */, /* no Gone: not listed */ };
    Some(Entry { id: k.pos(), sender: k.stamp.actor, time: k.stamp.shown().0, valid: part.valid, body, /* .. */ })
}
w.at(c, schema::MSG).fire(&message_of(d, r))?;
let q = CommitQuery { from, limit: Some(limit), kinds: vec![CommitKind::Content], ..Default::default() };
let page = db.at(c, schema::MSG).fired(&q)?;
db.at(c, schema::MSG).on_fire(move |db, ev| match ev { CommitEvent::Commit { commit, .. } => /* entry_of */ });
```
`commit.at(t, k)` is the `db.at(t, k)` / `w.at(t, k)` address read off a commit: one word, the same pair.

## Key types
Codegen emits `Aspect<T>` for a value aspect and `Signal<T>` for a `~` declaration. History is not in the key: whether a write is kept is a run-time fact (the thing's history setting). Methods are bounded by traits on the key:
- Value key (`Aspect`, `DynamicAspectKey`): `get`, `path`, `on_change`, `writes`, `on_write`, `edit_text`, `keep_alive`, and on `w.at(t, k)` the value writes (`set`, `remove`, `edit`, `overwrite`, path ops).
- Signal key (`Signal`, `DynamicAspectKey`): `fired`, `on_fire`, and on `w.at(t, s)` only `fire(v)` (one whole value) and `purge`.
- Both: `purge`, `retention` (who may purge the part), `commit.at`. A compile-fail doc test per crossing (`get`, `on_write`, `set` on a `Signal`; `fire`, `on_fire` on an `Aspect`).

Not at compile time:
- `DynamicAspectKey` (generic tools, schema known at run time): reads answer by the rules, no error: a signal's `get` reads absent and its `writes` list nothing; a value aspect's `fired` lists nothing. A value write on a signal or `fire` on a value aspect is `Invalid` at `commit()`: a write never silently does nothing.
- Ephemeral (`+`) rules (no purge on ephemeral ops; durable beside ephemeral in one `Write`) and the other `commit()` clashes stay runtime `Invalid`: they are across keys in one `Write`, which types do not see. Ephemeral aspects are governed by the thing's setting like durable ones.

## Undo touches only kept history
**Rule (Tess): undo, redo and `revert` of a commit work only while the commit is in kept history by its thing's setting, and write back content only from kept history. Anything else is `NotUndoable{NotKept}`, whether or not the bytes are still held here.** The API never exposes history the setting does not define as kept, so compaction, arrival order and timing cannot change what undo does.
- The target: each part it reverts must be kept by the setting at the undo's `ts` (`bounds::setting_keeps`: replaced, in history; live, kept while live, spec/commits.md §5), by the settings alone, never by what is held. So on an aspect no setting keeps, nothing is undone, an insert or a first set included, on the writer and every other node alike. Excepted, as they need no stored content: a signal's part, the creation record and parts on the things the commit created (undoing a creation deletes them), `retention^.0`, and a `group.0` part whose writes still in the group's current state only list things the commit created (`undo::lists_only`, read from the state's winners, never the part's body, so compaction cannot change it: the deletion removes them from every group the node may write).
- The pre-state: kept history is the listed parts (above), on every node alike, so whether an undo works is a function of the history setting and the edit's age, never of which node made it, whether the node restarted, or storage housekeeping. A kept part `NotFetched` yet is `NotUndoable{NotKept}` until it arrives.
- Whether an inverse needs replaced content is decided by the op's kind, never by what is held: an op whose inverse only removes its own content (a sequence insert, a set or bag add, a creation, a map entry's creation) needs only the target kept; a register or value set is `NotUndoable{NotKept}` unless the parts it may have replaced are kept too. A write does not record what it overwrote (spec/crdt.md §5.1), so these are every part of the aspect before it, unless a kept part supersedes it (a whole-aspect write stamped after it, or, for a delta without expiry, a snapshot whose frontiers or `Absorbed` reach it: that snapshot holds what it left live), each judged by its own retention counted from the undone write's `ts` (an unkept one that died earlier blocks too: judging by its body would depend on whether it is still held; a part not fetched yet and a forgotten ephemeral commit block as well; a snapshot not naming a part does not excuse it, since its writer may never have applied it); the undone write's own retention counts only for its redo. A first set replaced nothing: it undoes to absent. With kept history the inverse is computed from the kept parts, so an edit older than its keep bound is `NotUndoable` by age. Redo of an undo needs the undone value back, so it works only while that value is kept. Revert's skip rule (`Superseded`) and the creation rule (spec/crdt.md §4.6) stand; `undo_target`/`redo_target` fail as the call would, so a UI disables its button by them.
- No undo buffer or ephemeral undo log: content comes only from kept parts (computed from them where the undo reads, `undo::kept_before`). An ephemeral commit is undone by an ephemeral undo commit, as a durable one is.
- Where undo matters, the app says so: things with user-edited aspects get a setting keeping a day of history at creation (kit and app). The default stays "no history promised": such an aspect undoes nothing.
- Per-actor undo (notes/client-port.md) is unchanged: history only supplies content. Chat does not undo; kit's Undo is per thing over this account's commits (callers).
- Rejected: undo from whatever is held (exposes housekeeping, the leak); a local undo log beside history (a second mechanism, whose answer depends on the node and its restarts); a per-session undo stack in the API (a third undo model).

## Every read can subscribe itself
The principle's first sentence makes this possible: a read and its listener share an address, so a handle may do both. `ReadSet` and `db.tracking(&set) -> ReadOnly` (notes/api.md Watching) are this one read API with subscribing added at the same call; there is no second read path. Reads with no public listener (`aspects` as names, `groups_of`, `role_on`, `holders`, `has_content`, `created`, `changed`, `profile_of`) get an internal one that re-reads and compares; one without any address it can honestly name is not on `ReadOnly`.

## Local writes are always included
`origin` says `Local`; `commit.stamp.node` says which node. No option to exclude them: every use case is narrower than "local". A text session must see another session's or a `remove`'s writes (Text sessions); a bridge skips its own echo by commit id or value; a "new message" sound skips `commit.stamp.actor == me`; osis writes are local and synchronous, so there is no optimistic state to protect.

## When it fires
**A listener is due when a storage transaction ends having changed what it reads; when called it reads its address then.** It never shows a state from inside a transaction, and a commit that leaves a listing and comes back is told each time it reads otherwise. Callbacks run on the one dispatcher, in order, outside locks, any call allowed inside. Commits come from `Core::commit_changes` at the end of the transaction, with `listing::listing_moved`: a join tells each commit it superseded that no longer reads as listed, a rebuild compares the aspect's whole listing before and after; durable and ephemeral signal fires go through the same list.

## Text sessions
A session follows its field's value, whoever writes it (another session, a `remove`, an undo, a remote node):
- Its `base` is the text as last committed or merged. It is not a value listener: a value listener's coalescing compares with what it was last told, which is right for a reader (A, B, A within one dispatch tells it nothing new), but a session also learns the field from its own commits, so its own commit then a `remove` would read as no change. So it hears every change of its aspect (the subscription under the path listener, without its comparison) and reads its path itself, under its save lock (a value read before its own last save would look like another writer's).
- A call whose value equals `base` changes nothing (its own commit's echo, an unrelated write): pending typing stays pending, so one commit per pause holds.
- Another value: commit pending typing (the crdt rebases it), read the merged text, set `base` and the buffer to it, report splices through `on_merge`. A removed field reads empty.
- So two sessions on one field share it, clearing a draft is a plain `remove`, and an undo shows in open sessions.

## Numbers
A day's history on user-edited aspects (notes/arbitrary-values.md): at 0 nothing undoes; unbounded, every replaced body is kept forever. A day covers an editing session and a restart at the cost of a day's replaced bodies. Cost: one path read per path listener on a written aspect; a skip by op path only if measured.

## Properties (steps 1-8)
Each with its small tests; tests cite these by step number.
1. **Ephemeral signals are commits.** Every signal fire, durable or ephemeral, local or remote, reaches the aspect's commit listener once per time it reads otherwise, and `on_change`/`on_thing_change` hear nothing from it; a slow port client past its push bound hears its watch end (`Ended`). Tests: a local ephemeral signal is one event and an empty page; two nodes, heard once; through a thin client; a slow port client past the bound.
2. **Undo touches only kept history.** Whether an undo, redo or revert succeeds and what it writes is a function of kept history: the target must be kept by the setting, the same on every node, never of held-but-unkept bodies. Ephemeral undo runs on memory commits' kept history like durable undo; the thing's setting governs ephemeral aspects too. Kit and the app write a setting keeping a day of history (`keep_a_day`) on the things they create and on the groups holding them (undoing a delete or a membership removal and redoing an undone creation write memberships back). Tests: a register set twice with no history: undo is `NotUndoable`, before and after reopen; with a keeping setting it works after reopen and from a second node; the same edit undone with its replaced body held and compacted gives one outcome; an insertion or a first set without history is `NotUndoable` at once on the writer and every other node, held or compacted; with history it undoes and redoes while kept and is refused once it leaves history by the setting's bound; an ephemeral aspect a setting keeps undoes a replace, one without is `NotUndoable`.
3. **One commit model.** At every address a commit is listed exactly while it has a listed part there, and an item shows every listed part the caller may read. Tests: a two-thing commit listed at one aspect shows both parts; `at` decodes typed, a mismatching body reads `Held(None)` with `Mismatch`; a register without history lists only its live write, with history every write until the bound; a purged write lists `Purged`; another node's invalid write is not listed, our own is, marked; a thing listener hears a commit touching it and not one beside it, and no signal; a group listener hears a member's commit; a thin client sees only readable parts; `w.commit()` returns what a listing then shows.
4. **Key types.** Value operations do not compile on a signal key nor signal operations on a value key; a dynamic key's crossing writes are `Invalid` (compile-fail doc tests).
5. **Path listeners.** A path listener is called exactly when the value at its path differs, after a transaction, from the value of its last call, from any cause (calls coalesce: a value in between may go untold). Tests: write map entry `a`: the `b` listener is not called, `a` once; remove `a`, delete the thing: `None`; a `set` of the whole map calls only changed entries; a validity flip calls it (`Derived`); a mismatch reads `None`; through a thin client; N listeners, one write, one call and N reads (counted).
6. **Sessions follow every write.** An open session's buffer is the field's value merged with its pending typing, whoever wrote the field; its own echoes neither report nor commit. Tests: `remove` empties an open session; two sessions on one field keep both texts; an own commit reports and commits nothing (count commits); an undo shows; a remote edit still merges.
7. **Callers.** Kit keeps one session per editor (each editor hears others' typing through its own `on_merge` once committed) and disables Undo by `undo_target`; an undo shows in open sessions with no close or forced rebuild; Send commits the draft sessions, then clears them; Delete commits pending typing first (`commit`). Tests: kit's session tests, the send-clears-draft and undo app tests (a second rename undoes back to the first after reopen), with editors left open.
8. **Node state granularity**: one node-state write re-renders one node (kit `graph::one_node_state_write_renders_one_node`).
