# Listener design (proposal)
> Summary: Proposal for one listener model and one commit concept: anything that can be read and changes has one listener at the same address (values: thing, aspect, path, grants, status; commits: listed and heard at an aspect, a thing, a group; diagnostics; disputes); a listed `Commit` is the whole commit as this node may read it, with a typed `commit.at(t, k)`; a part is listed while it is in the read, kept by its history, or a tombstone; signal and history-keeping keys are their own key types, so misuse fails to compile; every listener hears local writes and fires after a transaction ends; text sessions follow their field's value. Build steps at the end. Open for Tess where marked.

Status: proposal. Nothing here is built. Inputs: issues/ui-state-watch-granularity.md, issues/ui-state-session-local-writes.md, issues/signal-fires-again.md (branch `signal-fire`), issues/history-verified-or-absent.md (H3). Judged against notes/api-design.md and notes/coordination.md (Design principles).

## Principle
**Every read that can change has one listener, at the same address, called when that read's answer differs, whoever caused it.** Two kinds of read, one set of rules:
- A **value** (has a "now"): called once with the current value, then with the value when it differs. Calls coalesce; equal values are skipped.
- A **list of commits** (no "now"): called once per commit whose listed form reads otherwise. No initial call (read a page after subscribing). Commits never coalesce.

A signal has no current value, only commits (spec/requirements.md), so it is read only as commits. Granularity comes from the address: to hear one map entry, listen at that entry's path.

## What you can listen to
| Read | Listener | Kind |
|---|---|---|
| `db.at(t, k).get()` | `db.at(t, k).on_change(f)` (`Change<K::T>`) | value |
| `db.at(t, k).path(p).get::<U>()` | `db.at(t, k).path(p).on_change::<U>(f)` | value |
| `db.aspects(t)` + each aspect | `db.on_thing_change(t, f)` | value |
| `db.grants(t)` / `db.status()` | `db.on_grants_change(t, f)` / `db.on_status_change(f)` | value |
| `db.at(t, k).commits(&q)` (kept or signal key) | `db.at(t, k).on_commit(f)` | commits |
| `db.commits(&scope, &q)` (`Scope::{Thing, Group, Aspects}`) | `db.on_commit(&scope, f)` | commits |
| diagnostics / `db.disputes()` | `db.on_diagnostic(f)` / `db.on_dispute(f)` | entries |
| a `TextSession`'s text | `session.on_merge(f)` | value (as splices) |

Value listeners say `change`, commit listeners `commit`. The typed aspect address and `Scope::Aspects` list by one rule; they are the typed and untyped views of one read, as `at(t, k).get()` and `path(p![]).get::<Value>()` are. `Scope` is also what `undo`/`redo` range over.

Rejected: an `on_write` listing with write-named types beside the commit query (two concepts for one commit list); `on_signal` for signal keys only (history-keeping aspects would still need a second listing, and a signal write is a commit like any other).

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
- **Parts**: every part of the commit this node holds and the caller may read, on any thing, with its value from the commit's own body (a superseded one reads as written). `Held(None)`: a removal, or not a whole value of `K::T` (a `Mismatch` diagnostic, as for any typed read; the untyped key shows it). Decoding happens in `at`, so parts nobody asks for cost no typed read.
- **Which parts are listed**, one rule at every address: a part is listed while it is in its aspect's read, or kept by its retention's history (until the keep bound), or a purge tombstone where it would otherwise be listed, or this node's own invalid write (kept, marked, so its user may write it again). Replaced with no history kept, expired, compacted, another node's invalid body: not listed anywhere. **A commit is listed at an address while it has a listed part there.** So an aspect keeping history lists every write until its bound; an aspect keeping none lists only commits still in its read; every synced node lists the same commits (H3). "Replaced" is revert's skip rule (spec/crdt.md §4.6): everything the part wrote is overwritten since.
- `CommitQuery { from: CommitFrom, limit: Option<usize>, actors, kinds, reverts, reverted_by, in_effect }` (plain struct, `Default`; empty filters match all). `CommitFrom::{Newest, Oldest, Before(CommitPos), After(CommitPos)}`, neither bound counting itself; `CommitPos::time(t)` a time. `CommitPage { commits, more, complete }`: `more` past `limit`, an internal cap or the read limit; `complete: false` while a label carrying the address has not finished a pass here (commits may yet arrive anywhere).
- `CommitEvent::{Commit { id, commit: Option<Commit> }, Reread, Ended(Error)}`: a commit as it reads when delivered (new, late, validity flip, body arriving, purged; `None`: no longer listed here). An ephemeral signal is the one commit nobody holds: its event carries it as it arrived, no page shows it.
- Undo and redo keep their rule over this actor's held commits in the scope; `undo_target` fails `NotUndoable` as `undo` would, so it never names a commit with nothing listed.
- Cost (stated, not optimized): a listed commit reads all its readable parts; commits touch about 1.1 things. A listener at a thing or group checks each changed commit's touched things against its scope at the transaction's end: O(changed commits × such listeners).

## Accessor in use: chat's history
Before:
```rust
fn entry_of(e: HistoryEntry<schema::Message>) -> Option<Entry> {
    if e.kind != CommitKind::Content { return None; }
    let (body, replaces) = match e.body { HistoryBody::Held(v) => /* decode */, HistoryBody::Gone => (Body::Gone, None), /* .. */ };
    Some(Entry { id: e.pos(), sender: e.commit.actor, time: e.commit.shown().0, valid: e.valid, body, /* .. */ })
}
let page = db.at(c, schema::MSG).history(from, limit)?;            // page.entries
db.at(c, schema::MSG).on_history(move |db, ev| match ev { HistoryEvent::Commit { entry, .. } => /* entry_of */ });
```
After:
```rust
fn entry_of(c: Tid, k: &Commit) -> Option<Entry> {
    let part = k.at(c, schema::MSG)?;
    let (body, replaces) = match part.body { osis::Body::Held(v) => /* decode */, /* no Gone: not listed */ };
    Some(Entry { id: k.pos(), sender: k.stamp.actor, time: k.stamp.shown().0, valid: part.valid, body, /* .. */ })
}
let q = CommitQuery { from, limit: Some(limit), kinds: vec![CommitKind::Content], ..Default::default() };
let page = db.at(c, schema::MSG).commits(&q)?;                     // page.commits
db.at(c, schema::MSG).on_commit(move |db, ev| match ev { CommitEvent::Commit { commit, .. } => /* entry_of */ });
```
`commit.at(t, k)` is the `db.at(t, k)` / `w.at(t, k)` address read off a commit: one word, the same pair.

## Misuse fails to compile
Codegen emits one key type per declaration: `Aspect<T>` (no history: the default, unnamed), `KeptAspect<T>` (`keep_history`), `Signal<T>` (`~`; the schema already refuses a durable signal without `keep_history`). Methods are bounded by traits on the key:
- `get`, `path`, `on_change`, `edit_text`, `keep_alive` and value writes need a value key (`Aspect`, `KeptAspect`, `DynamicAspectKey`): none compile on a `Signal`.
- `commits` and `on_commit` at an aspect need a listed key (`KeptAspect`, `Signal`, `DynamicAspectKey`): listing a plain `Aspect` does not compile.
- `w.at(t, signal)` offers only `set` (one root set) and `purge`: a signal path op, `remove`, `edit` or `overwrite` can never be valid, so it cannot be written.
- A compile-fail doc test per rule.

Not at compile time:
- `DynamicAspectKey` (generic tools, schema known at run time): the rules answer, no error. A signal reads absent; listing an aspect keeping no history lists the commits still in its read.
- Per-write retention and a thing's required rules choose history at run time; the key type states the schema's declaration. A plain key's writes kept that way are listed at a thing, a group, `Scope::Aspects` or a dynamic key, not through the typed key. Question 4.
- Ephemeral (`+`) rules (no retention or purge on ephemeral ops; durable beside ephemeral in one `Write`) and the other `commit()` clashes stay runtime `Invalid`: they are across keys in one `Write`, which types do not see, and a third key axis multiplies types. A thing's record beside an expiring write is to become legal (issues/creation-record-ordinary.md), so it gets no compile check.

## Local writes are always included
`origin` says `Local`; `commit.stamp.node` says which node. **No option to exclude them.** The use cases, checked:
- A text session ignoring its own commits wants "not my own commits", not "not this node's": another session or a `remove` on the node is what it must see. Solved by comparing values (Text sessions).
- A bridge mirroring osis elsewhere skips only its own echo (its commit ids, or value equality); a node-wide filter drops other local code's writes.
- A "new message" sound skips one's own: `commit.stamp.actor` in the callback, one line.
- Optimistic UI: osis writes are local and synchronous; there is no optimistic state to protect.
Every case is narrower than "local", so an option would be a knob wrong for each of them.

## When it fires
One rule: **a listener is due when a storage transaction ends having changed what it reads; when called it reads its address then.** It never shows a state from inside a transaction, and a commit that leaves a listing and comes back is told each time it reads otherwise. Callbacks run on the one dispatcher, in order, outside locks, any call allowed inside. Commits come from `Core::history_changes` at the end of the transaction (built; signal-fire moves durable signals onto it; ephemeral signals join in step 1). `Delivery::Fired` and the per-commit `signals` lists go.

## Text sessions
A session follows its field's value, whoever writes it (another session, a `remove`, an undo, a remote node):
- It listens at its own path. Its `base` is the text as last committed or merged.
- A call whose value equals `base` changes nothing (its own commit's echo, an unrelated write): pending typing stays pending, so one commit per pause holds.
- Another value: commit pending typing (the crdt rebases it), read the merged text, set `base` and the buffer to it, report splices through `on_merge`. A removed field reads empty.
- So two sessions on one field share it, clearing a draft is a plain `remove`, and an undo shows in open sessions. `on_merge` reports any change merged into the buffer, local ones included, so `on_remote` would be wrong.

## API before and after
Gone: `HistoryEntry`, `HistoryBody` (its `Gone`: not listed), `HistoryPage`, `HistoryEvent`, `HistoryFrom`, `HistoryPos`, `AspectRef::history`, `AspectRef::on_history`, `CommitEntry` (its `aspects`, `content_gone`, `purged` fold into parts), `CommitQuery::{scope, since, until, after}`, the unscoped commit query, `Delivery::Fired`, the `signals` of `Event::Ephemeral` (signal-fire removes those of `Applied`/`Joined`), signal firing through `on_change`/`on_thing_change`, the port's fired-signal Notify, `TextSession::on_remote`.
New: `Commit` as above (replacing the two-field `Commit`; `w.commit()`, `revert`, `undo`, `redo` return it, `undo_target`/`redo_target` name it), `Part`, `Body`, `CommitPage`, `CommitEvent`, `AspectRef::{commits, on_commit}`, `Osis::{commits(&Scope, &CommitQuery), on_commit}`, `KeptAspect<T>`, `Signal<T>`, the value-key and listed-key bounds, `PathRef::on_change::<U>`.
Renamed: `HistoryFrom` to `CommitFrom`, `HistoryPos` to `CommitPos`, `on_remote` to `on_merge`; `port::SIGNAL_BYTES` to a name for its job (pushed commits and diagnostics for a slow client), e.g. `PUSH_BYTES`.
Unchanged: `on_change`, `on_thing_change`, `on_grants_change`, `on_status_change`, `on_diagnostic`, `on_dispute`, `Change`, `Origin`, `Stamp`, `Scope`, `CommitKind`, `Subscription`, the dispatcher.

Callers:
- **libs/chat**: `entries`, `entry_at`, `on_event` as above; its `Body::Gone` goes; `Id` is `CommitPos`.
- **kit**: `store.rs` `changed` uses `db.changed`, `next_undo` uses `db.undo_target` (both reimplement them over the commit query). `view/sessions.rs` back to one session per editor (sharing existed only for the session bug). Node state re-render through path listeners per shown node (kit's design, an app-session task).
- **app**: `log.rs` Send: `session.commit()` then clear the drafts, no `close_key`, no rebuild; `about.rs` Undo and `opener.rs` drop `sessions.close` and the forced rebuild.
- **cli**: `history T AK` and `commits` merge into `commits` at an address (`T AK`, `--thing T`, `--group G`, `--aspect T AK...`) with `--follow` for `on_commit`; each line a commit with its parts. `watch T AK [PATH]` as `get`; on a signal key it says to use `commits --follow`.
- **client port**: the history page and commit query requests become one commit request at an address; the history subscription becomes a commit subscription at an aspect, thing, group or aspect set; the aspect value filter takes a path (`[0, tid, ak, path]`, in place); a thin client's parts are what its actor may read.
- Tests naming the gone types: `core/osis/tests/it/{api,commits,history,ephemeral,ephemeral_undo,port,port_clients,sync,watch,sources,notes,contact,serving,keep_clients}.rs`, `core/osis/src/lib.rs` examples.

Checklist (notes/api-design.md): (1) history and the commit query were one concept at two addresses: merged; (2) every merged type removed in the change; (3) no new word: commit, part, body, address are in use; `KeptAspect`/`Signal` name the schema's own words; (4) nothing internal exposed, no new number; (5) shape: value vs commits is the only split, decided by the contract; one `Commit` type with a typed accessor, not a typed and an untyped item; (6) connected handle: the port carries both; offline: local; deleted thing: values read `None`, its commits stay listed by the rule; empty `Scope::Aspects`: lists nothing; (7) notes/api.md Watching, Signals, History, Commits, Text sessions, Keys and the `lib.rs` examples are rewritten in the build.

Numbers (notes/arbitrary-values.md): none added. Cost: one path read per path listener on a written aspect; a skip by op path only if measured.

## Questions for Tess
1. No option to exclude local writes (reasons above). Agree?
2. `on_merge` as the name for a session's "your text changed under you" listener.
3. A replaced write with no history kept leaves every listing, a thing's and a group's too, so those no longer show commits whose every write was overwritten (only the commits still in the read, plus kept history). That is "no history unless specified" applied to the commit list; undo is unaffected. Agree?
4. History chosen at run time (per-write retention, required rules) on a key declared without `keep_history` is listed only at thing, group and untyped addresses. Keep that, or decide history only by the schema (no per-write history), which would make the key type exact? Leaning: keep; a key meant to be listed declares `keep_history`.

## Build steps
Each one worker plus a reviewer, in order; each names its property and its small tests.
1. **Ephemeral signals are commits** (after `signal-fire` merges). Property: every signal write, durable or ephemeral, local or remote, reaches the aspect's commit listener (`on_history` until step 2) once per time it reads otherwise, and `on_change`/`on_thing_change` hear nothing from it. Engine queues ephemeral signal arrivals and own sends into the end-of-transaction list; delete `Delivery::Fired`, `Event::Ephemeral.signals`, the port's fired Notify. Tests: a local ephemeral signal is one event and an empty page; two nodes, heard once; through a thin client; a slow port client past the bound gets `Reread`.
2. **One commit model.** Property: at every address a commit is listed exactly while it has a listed part there, and an item shows every part the caller may read with its value. `Commit`, `Part`, `Body`, `CommitQuery`/`CommitPage`/`CommitEvent`, `AspectRef::{commits, on_commit}` (bound by kept or signal key at run time until step 3), `Osis::{commits, on_commit}`, the port, CLI `commits`, chat, kit `changed`/`next_undo`; every gone type deleted. Absorbs H3 (issues/history-verified-or-absent.md, retention step 5). Tests: a two-thing commit listed at one aspect shows both parts; `at` decodes typed, a mismatching body reads `Held(None)` with `Mismatch`; a register without history lists only its live write, with history every write until the bound; a purged write lists `Purged`; another node's invalid write is not listed, our own is, marked; a thing listener hears a commit touching it and not one beside it; a group listener hears a member's commit; thin client sees only readable parts; `w.commit()` returns what a listing then shows.
3. **Key types.** Property: `get`/`on_change` on a signal and listing a plain aspect do not compile; signal writes are root sets only. Codegen `KeptAspect<T>`, `Signal<T>`; bounds; compile-fail doc tests; update notes/api.md Keys and spec/data-model.md §2.
4. **Path listeners.** Property: a path listener is called exactly when the value at its path differs after a transaction, from any cause. Tests: write map entry `a`: the `b` listener is not called, `a` once; remove `a`, delete the thing: `None`; a `set` of the whole map calls only changed entries; a validity flip calls it (`Derived`); a mismatch reads `None`; through a thin client; N listeners, one write, one call and N reads (counted).
5. **Sessions follow every write.** Property: an open session's buffer is the field's value merged with its pending typing, whoever wrote the field; its own echoes neither report nor commit. Tests: `remove` empties an open session; two sessions on one field keep both texts; an own commit reports and commits nothing (count commits); an undo shows; a remote edit still merges.
6. **Callers.** kit sessions one per editor, app Send/Undo/opener without close or forced rebuild. Tests: kit's session tests, the send-clears-draft and undo app tests, rewritten with editors left open.
7. **Node state granularity** (app session with Tess): one node-state write re-renders one node. Test: count node rebuilds for one `ui:week.0` entry write.
