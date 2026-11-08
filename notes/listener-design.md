# Listener design (proposal)
> Summary: Proposal for one listener model and one `Commit` type: every read that changes has one listener at its address (values: `on_change`; a value aspect's or a scope's commits: `writes`/`on_write`; a signal's: `fired`/`on_fire`; diagnostics; disputes); `Signal<T>` keys make values and signals distinct at compile time (`fire` fires, value ops don't compile on it); a part is listed while in the read, kept by history, or a tombstone; undo writes back only kept history, else `NotUndoable`, with user-edited aspects declaring `keep_history(1d)`; every listener hears local writes after a transaction ends; text sessions follow their field. Build steps at the end.

Status: proposal; Tess decided the shape (local writes, per-write history, `Signal<T>`, the fire names, the undo leak), the rest awaits her go. Build steps 1 (ephemeral fires reach `on_history`; a port lapse past `PUSH_BYTES` ends the watch, `Ended`, as every lapse does) and 2 (undo from kept history only) are built; the rest is not. Inputs: issues/ui-state-watch-granularity.md, issues/ui-state-session-local-writes.md, issues/signal-fires-again.md (branch `signal-fire`), issues/history-verified-or-absent.md (H3). Judged against notes/api-design.md and notes/coordination.md (Design principles).

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
pub struct Part<T> { pub valid: bool, pub body: Body<T> }
pub enum Body<T> { Held(Option<T>), TooLarge { limit: u64 }, Purged { by: CommitId, actor: Option<Tid> }, NotFetched }
```
- **Parts**: every listed part of the commit the caller may read, on any thing, value or signal, with its value from the commit's own body (a superseded one reads as written). `Held(None)`: a removal, or not a whole value of `K::T` (a `Mismatch` diagnostic, as for any typed read; the untyped key shows it). Decoding happens in `at`, so unread parts cost no typed read. `AspectKey` covers both key kinds: reading a part is neither writing nor firing.
- **Which parts are listed**, one rule at every address: a part is listed while it is in its aspect's read, or kept by history (the aspect's `keep_history`, a per-write retention or a required rule, until the keep bound), or a purge tombstone where it would otherwise be listed, or this node's own invalid write (kept, marked, so its user may write it again). Replaced with no history kept, expired, compacted, another node's invalid body: not listed anywhere, whatever this node still happens to hold. **A commit is listed at an address while it has a listed part there.** An aspect keeping history lists every write until its bound; one keeping none lists only commits still in its read; listing an aspect whose writes keep no history is no error. Every synced node lists the same commits (H3). Ephemeral commits list by the same rule; their kept history is in memory, as their values are. "Replaced" is revert's skip rule (spec/crdt.md §4.6): everything the part wrote is overwritten since.
- `CommitQuery { from: CommitFrom, limit: Option<usize>, actors, kinds, reverts, reverted_by, in_effect }` (plain struct, `Default`; empty filters match all). `CommitFrom::{Newest, Oldest, Before(CommitPos), After(CommitPos)}`, neither bound counting itself; `CommitPos::time(t)` a time. `CommitPage { commits, more, complete }`: `more` past `limit`, an internal cap or the read limit; `complete: false` while a label carrying the address has not finished a pass here.
- `CommitEvent::{Commit { id, commit: Option<Commit> }, Reread, Ended(Error)}`: a commit as it reads when delivered (new, late, validity flip, body arriving, purged; `None`: no longer listed here). An ephemeral signal is the one commit nobody holds: its `on_fire` event carries it as it arrived, no page shows it.
- Cost (stated, not optimized): a listed commit reads all its readable parts; commits touch about 1.1 things. A scope listener checks each changed commit's touched things against its scope at the transaction's end: O(changed commits × scope listeners).

## Accessor in use: chat's messages
Messages are the durable signal `chat:msg~0` (`keep_history(forever)`). The UI still says "send"; the code fires.
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
Codegen emits `Aspect<T>` for a value aspect and `Signal<T>` for a `~` declaration. History is not in the key: whether a write is kept is a run-time fact (per-write retention, required rules, an app's history setting). Methods are bounded by traits on the key:
- Value key (`Aspect`, `DynamicAspectKey`): `get`, `path`, `on_change`, `writes`, `on_write`, `edit_text`, `keep_alive`, and on `w.at(t, k)` the value writes (`set`, `remove`, `edit`, `overwrite`, path ops).
- Signal key (`Signal`, `DynamicAspectKey`): `fired`, `on_fire`, and on `w.at(t, s)` only `fire(v)` (one whole value) and `purge`.
- Both: `purge`, `commit.at`. A compile-fail doc test per crossing (`get`, `on_write`, `set` on a `Signal`; `fire`, `on_fire` on an `Aspect`).

Not at compile time:
- `DynamicAspectKey` (generic tools, schema known at run time): reads answer by the rules, no error: a signal's `get` reads absent and its `writes` list nothing; a value aspect's `fired` lists nothing. A value write on a signal or `fire` on a value aspect is `Invalid` at `commit()`: a write never silently does nothing.
- Ephemeral (`+`) rules (no purge on ephemeral ops; durable beside ephemeral in one `Write`) and the other `commit()` clashes stay runtime `Invalid`: they are across keys in one `Write`, which types do not see. Ephemeral aspects take `keep_history` (schema or per write) like durable ones.

## Undo writes back only kept history
**Rule: undo, redo and `revert` write back content only from kept history. Where the inverse needs anything else, it is `NotUndoable{ContentGone}`, whether or not the bytes are still held here.**
- Kept history is the listed parts (above), on every node alike, so whether an undo works is a function of the history setting and the edit's age, never of which node made it, whether the node restarted, or storage housekeeping. A kept part `NotFetched` yet is `NotUndoable{ContentGone}` until it arrives.
- Without kept history, whether an inverse needs replaced content is decided by the op's kind, never by what is held: an op whose inverse only removes its own content (a sequence insert, a set or bag add, a creation, a map entry's creation) undoes without history; a register or value set is `NotUndoable{ContentGone}` unless the parts it may have replaced are kept. A write does not record what it overwrote (spec/crdt.md §5.1), so these are every part of the aspect before it with writes of its own, unless a kept part supersedes it (a whole-aspect write stamped after it, or a snapshot whose frontiers or `Absorbed` reach it: that snapshot holds what it left live), each judged by its own retention counted from the undone write's `ts` (an unkept one that died earlier blocks too: judging by its body would depend on whether it is still held; a part not fetched yet and a forgotten ephemeral commit block as well; a snapshot not naming a part does not excuse it, since its writer may never have applied it); the undone write's own retention counts only for its redo. A first set replaced nothing: it undoes to absent. With kept history the inverse is computed from the kept parts, so an edit older than its keep bound is `NotUndoable` by age. Redo of an undo needs the undone value back, so it works only while that value is kept. Revert's skip rule (`Superseded`) and the creation rule (spec/crdt.md §4.6) stand; `undo_target`/`redo_target` fail as the call would, so a UI disables its button by them.
- No undo buffer or ephemeral undo log: content comes only from kept parts (rare path, computed from them, `undo::kept_before`). An ephemeral commit is undone by an ephemeral undo commit, as a durable one is.
- Where undo matters, the schema says so: user-edited aspects declare `keep_history(1d)` (Build step 2 lists them). The default stays "no history promised": such an aspect undoes only what takes something away.
- Per-actor undo (notes/client-port.md) is unchanged: history only supplies content. Chat does not undo; kit's Undo is per thing over this account's commits (callers).
- Rejected: undo from whatever is held (exposes housekeeping, the leak); a local undo log beside history (a second mechanism, whose answer depends on the node and its restarts); a per-session undo stack in the API (a third undo model).

## Local writes are always included
`origin` says `Local`; `commit.stamp.node` says which node. No option to exclude them: every use case is narrower than "local". A text session must see another session's or a `remove`'s writes (Text sessions); a bridge skips its own echo by commit id or value; a "new message" sound skips `commit.stamp.actor == me`; osis writes are local and synchronous, so there is no optimistic state to protect.

## When it fires
**A listener is due when a storage transaction ends having changed what it reads; when called it reads its address then.** It never shows a state from inside a transaction, and a commit that leaves a listing and comes back is told each time it reads otherwise. Callbacks run on the one dispatcher, in order, outside locks, any call allowed inside. Commits come from `Core::history_changes` at the end of the transaction (signal-fire moves durable signals onto it; ephemeral signals join in step 1).

## Text sessions
A session follows its field's value, whoever writes it (another session, a `remove`, an undo, a remote node):
- It listens at its own path. Its `base` is the text as last committed or merged.
- A call whose value equals `base` changes nothing (its own commit's echo, an unrelated write): pending typing stays pending, so one commit per pause holds.
- Another value: commit pending typing (the crdt rebases it), read the merged text, set `base` and the buffer to it, report splices through `on_merge`. A removed field reads empty.
- So two sessions on one field share it, clearing a draft is a plain `remove`, and an undo shows in open sessions.

## API before and after
Gone: `HistoryEntry`, `HistoryBody`, `HistoryPage`, `HistoryEvent`, `AspectRef::{history, on_history}`, `CommitEntry` (its `aspects`, `content_gone`, `purged` fold into parts), `Osis::commits` (unscoped, `CommitQuery::{scope, since, until, after}`), `Delivery::Fired`, the `signals` of `Event::Ephemeral` (signal-fire removes those of `Applied`/`Joined`), signals through `on_change`/`on_thing_change`, `set` on a signal, the port's fired-signal Notify, `TextSession::on_remote`, undo from held-but-unkept bodies, the ephemeral undo log (`Eph.log`, `Config.ephemeral_undo_bytes`, `ephemeral_history`, ephemeral `NotUndoable{Compacted}`, `BatchId::Ephemeral`: an ephemeral write is named by its commit id).
New: `Commit` as above (replacing the two-field `Commit`), `Part`, `Body`, `CommitPage`, `CommitEvent`, `AspectRef::{writes, on_write, fired, on_fire}`, `Osis::{writes(&Scope, &CommitQuery), on_write}`, `Signal<T>`, `fire`, the value-key and signal-key bounds, `PathRef::on_change::<U>`, `keep_history` on ephemeral aspects.
Renamed: `HistoryFrom`/`HistoryPos` to `CommitFrom`/`CommitPos`, `on_remote` to `on_merge`; `port::SIGNAL_BYTES` to a name for its job (pushed commits and diagnostics for a slow client), e.g. `PUSH_BYTES`.
Unchanged: `on_change`, `on_thing_change`, `on_grants_change`, `on_status_change`, `on_diagnostic`, `on_dispute`, `Change`, `Origin`, `Stamp`, `Scope`, `CommitKind`, `Subscription`, the dispatcher, `undo`/`redo`/`revert` signatures (they return `Commit`).

Callers:
- **libs/chat**: `fire`, `fired`, `on_fire` as above; its `Body::Gone` goes; `Id` is `CommitPos`.
- **kit**: `store.rs` `changed` uses `db.changed`, `next_undo` uses `db.undo_target` (both reimplement them over the commit query); Undo disables by `undo_target` and shows `NotUndoable` as "can't undo". `view/sessions.rs` back to one session per editor. Node state re-render through path listeners per shown node (an app-session task).
- **app**: `log.rs` Send: `session.commit()` then clear the drafts, no `close_key`, no rebuild; `about.rs` Undo and `opener.rs` drop `sessions.close` and the forced rebuild. Notes, tags, events and contacts undo back a day from any device (the tagged aspects).
- **cli**: `history T AK` and `commits` become `writes` at an address (`T AK`, `--thing T`, `--group G`, `--aspect T AK...`) and `fired T AK`, each with `--follow`; each line a commit with its parts. `watch T AK [PATH]` as `get`; on a signal it says to use `fired --follow`. `fire T AK VALUE` beside `set`.
- **client port**: history and commit query requests become one listing request at an address (writes or fired); subscriptions likewise; the aspect value filter takes a path (`[0, tid, ak, path]`, in place); a thin client's parts are what its actor may read; `fire` its own op name over the same write row.
- Tests naming the gone types: `core/osis/tests/it/{api,commits,history,ephemeral,ephemeral_undo,port,port_clients,sync,watch,sources,notes,contact,serving,keep_clients}.rs`, `core/osis/src/lib.rs` examples. App `share.rs`/`data.rs` undo tests hold under the rule unchanged: each undoes a first `name.0` set (writes nothing back) and a creation is not undone.

Checklist (notes/api-design.md): (1) history and the commit query were one concept at two addresses: merged; (2) every merged type removed in the change; (3) words in use: commit, part, body, write, fire; each act, listing and listener share a word; (4) nothing internal exposed: what undo can restore follows from history alone, no node-local bound; (5) shape: value vs commits split by contract, writes vs signals split by key type at compile time; one `Commit` with a typed accessor; (6) connected handle: the port carries both; offline: local; deleted thing: values read `None`, its commits stay listed by the rule; empty `Scope::Aspects`: lists nothing; (7) notes/api.md Keys, Watching, Signals, History, Commits, Text sessions and the `lib.rs` examples are rewritten in the build.

Numbers (notes/arbitrary-values.md): `ephemeral_undo_bytes` leaves the table. `keep_history(1d)` on user-edited aspects, minor consequence: at 0 undo only takes things away; unbounded, every replaced body is kept forever. A day covers an editing session and a restart at the cost of a day's replaced bodies. Cost: one path read per path listener on a written aspect; a skip by op path only if measured.

## Build steps
Each one worker plus a reviewer, in order; each names its property and its small tests.
1. **Ephemeral signals are commits** (after `signal-fire` merges). Property: every signal fire, durable or ephemeral, local or remote, reaches the aspect's commit listener (`on_history` until step 3) once per time it reads otherwise, and `on_change`/`on_thing_change` hear nothing from it. Engine queues ephemeral signal arrivals and own fires into the end-of-transaction list; delete `Delivery::Fired`, `Event::Ephemeral.signals`, the port's fired Notify. Tests: a local ephemeral signal is one event and an empty page; two nodes, heard once; through a thin client; a slow port client past the bound hears its watch end.
2. **Undo writes back only kept history.** Property: whether an undo, redo or revert succeeds and what it writes is a function of kept history, the same on every node, never of held-but-unkept bodies. Ephemeral undo runs on memory commits' kept history like durable undo (issues/eph-unify.md D); the ephemeral undo log goes; the schema allows `keep_history` on ephemeral aspects. Schema: `keep_history(1d)` on `name.0`, `body.0`, `tag.0`, `group.0` (core: undoing a delete or a membership removal and redoing an undone creation write memberships back) and every `event:` and `contact:` aspect; not on window state (`ui:*`, `osis_app:draft.0`/`reply_to.0`: no Undo offered there), `osis_app:color.0` (seeds), `ui:collection.0` (seeds). Tests: set a register twice with no history: undo is `NotUndoable`, before and after reopen; with `keep_history` it works after reopen and from a second node; the same edit undone with its replaced body held and compacted gives one outcome; undoing an insertion or a first set works without history; redo of that undo works only with history; an ephemeral aspect with `keep_history` undoes a replace, one without is `NotUndoable`.
3. **One commit model.** Property: at every address a commit is listed exactly while it has a listed part there, and an item shows every listed part the caller may read. `Commit`, `Part`, `Body`, `CommitQuery`/`CommitPage`/`CommitEvent`, `AspectRef::{writes, on_write, fired, on_fire}` (kind checked at run time until step 4), `Osis::{writes, on_write}`, the port, CLI, chat, kit `changed`/`next_undo`; every gone type deleted. Absorbs H3 (issues/history-verified-or-absent.md, retention step 5). Tests: a two-thing commit listed at one aspect shows both parts; `at` decodes typed, a mismatching body reads `Held(None)` with `Mismatch`; a register without history lists only its live write, with history (declared or per-write) every write until the bound; a purged write lists `Purged`; another node's invalid write is not listed, our own is, marked; a thing listener hears a commit touching it and not one beside it, and no signal; a group listener hears a member's commit; thin client sees only readable parts; `w.commit()` returns what a listing then shows.
4. **Key types.** Property: value operations do not compile on a signal key nor signal operations on a value key; a dynamic key's crossing writes are `Invalid`. Codegen `Signal<T>`, `fire`, bounds, compile-fail doc tests; update notes/api.md Keys and spec/data-model.md §2.
5. **Path listeners.** Property: a path listener is called exactly when the value at its path differs after a transaction, from any cause. Tests: write map entry `a`: the `b` listener is not called, `a` once; remove `a`, delete the thing: `None`; a `set` of the whole map calls only changed entries; a validity flip calls it (`Derived`); a mismatch reads `None`; through a thin client; N listeners, one write, one call and N reads (counted).
6. **Sessions follow every write.** Property: an open session's buffer is the field's value merged with its pending typing, whoever wrote the field; its own echoes neither report nor commit. Tests: `remove` empties an open session; two sessions on one field keep both texts; an own commit reports and commits nothing (count commits); an undo shows; a remote edit still merges.
7. **Callers.** kit sessions one per editor, Undo by `undo_target`; app Send/Undo/opener without close or forced rebuild. Tests: kit's session tests, the send-clears-draft and undo app tests (plus: a second rename undoes back to the first after reopen), rewritten with editors left open.
8. **Node state granularity** (app session with Tess): one node-state write re-renders one node. Test: count node rebuilds for one `ui:week.0` entry write.
