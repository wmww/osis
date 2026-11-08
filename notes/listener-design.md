# Listener design (proposal)
> Summary: Proposal for one listener model: anything that can be read and changes has one listener at the same address (values: thing, aspect, path, grants, status; entries: an aspect's history, diagnostics, disputes); values coalesce to the latest read, entries are told one by one; signals are entries only; every listener hears local writes and fires after a transaction ends; text sessions follow their field's value, whoever wrote it. Build steps at the end. Open for Tess where marked.

Status: proposal. Nothing here is built. Inputs: issues/ui-state-watch-granularity.md, issues/ui-state-session-local-writes.md, issues/signal-fires-again.md (branch `signal-fire`, which moves durable signals to `on_history`). Judged against notes/api-design.md and notes/coordination.md (Design principles).

## Principle
**Every read that can change has one listener, at the same address, called when that read's answer differs, whoever caused it.** Two kinds of read, so two kinds of listener, with one set of rules:
- A **value** (has a "now"): the listener is called once with the current value, then with the value when it differs. Calls coalesce: one call may show several transactions. Equal values are skipped.
- An **entry stream** (no "now", only entries): the listener is called once per entry that reads otherwise. No initial call (read a page after subscribing). Entries never coalesce with each other.

A signal "has no current value, only entries" (spec/requirements.md), so it is an entry stream and nothing else. Granularity comes from the address, not from a report inside the event: to hear one map entry, listen at that entry's path.

## What you can listen to
| Read | Listener | Kind |
|---|---|---|
| `db.at(t, k).get()` | `db.at(t, k).on_change(f)` (typed `Change<K::T>`) | value |
| `db.at(t, k).path(p).get::<U>()` | `db.at(t, k).path(p).on_change::<U>(f)` **new** | value |
| `db.aspects(t)` + each aspect | `db.on_thing_change(t, f)` (one `Change<Value>` per aspect) | value |
| `db.grants(t)` | `db.on_grants_change(t, f)` | value |
| `db.status()` | `db.on_status_change(f)` | value |
| `db.at(t, k).history(..)` | `db.at(t, k).on_history(f)` (signals: durable and ephemeral) | entries |
| diagnostics | `db.on_diagnostic(f)` | entries |
| `db.disputes()` | `db.on_dispute(f)` | entries |
| a `TextSession`'s text | `session.on_merge(f)` (renamed from `on_remote`) | value (as splices) |

Names: value listeners say `change`, entry listeners name the stream. The aspect and path pair is the existing `get` pair (aspect typed by the key, path by `U`), not a second way: `at(t, k).path(p![])` is the untyped view of the root, as for `get`.

Not adding:
- A "changed paths" list in `Change`. Derived changes (validity, expiry, purge, a late part) recompute a whole aspect, so the list could only be "these, or maybe everything": a weaker property than the path listener's exact one, and a second way to narrow.
- A map-only or top-level-only watch (Tess's stick). The path listener works at any depth of any type.
- Path scope on `on_history`: entries are per commit on an aspect; nothing has asked.

## What an event says
- Value: `Change<T> { tid, ak, value: Result<Option<T>>, origin }`, unchanged. A path listener's `value` is the value at its path (`None`: absent there, the thing deleted, or not a `U`: `Mismatch`). `origin` names the newest commit (or derived cause) folded into the call.
- Entries: `HistoryEvent::Commit { id, entry }` as now: the entry as it reads when delivered. An ephemeral signal is the one entry nobody holds, so its event carries the entry as it arrived, and no page ever shows it (held by none is the definition, not an exception).
- **Local writes are always included.** `origin` says `Local`; an entry's `commit.node` says which node.

**No option to exclude local writes.** The use cases, checked:
- A text session ignoring its own commits: what it wants is "not my own commits", not "not this node's"; another session or a `remove` on the same node is exactly what it must see. Solved by comparing values (below), with no origin test.
- A bridge mirroring osis to another system: it must skip only its own echo, and must mirror other local code's writes. Its commit ids (`Write::commit` returns them) or value equality do that; a node-wide filter would drop real changes.
- A "new message" sound: skip one's own; `origin`/`commit.actor` in the callback is one line.
- Optimistic UI: osis writes are local and synchronous, so there is no optimistic state to protect.
Every case is narrower than "local", so an option would be a knob that is wrong for each of them. osis as a local state system needs listeners to treat a local write like any other.

## When it fires
One rule: **a listener is due when a storage transaction ends having changed what it reads; when called it reads its address then.** So it never shows a state from inside a transaction (a write purged or judged invalid later in the same transaction is never seen), and a write that leaves history and comes back is told as an entry each time it reads otherwise. Callbacks keep running on the one dispatcher, in order, outside locks, any call allowed inside.
- Values already read at delivery; the rule changes nothing for them except that signals leave this path.
- Entries come from `Core::history_changes` at the end of the transaction (built); the signal-fire branch makes durable signals use it. Ephemeral signals join it in step 1.
- `Delivery::Fired` and the per-commit `signals` lists go: no listener fires at queue time any more.

## Text sessions
A session follows its field's value, whoever writes it (another session, a `remove`, an undo, a remote node):
- It listens at its own path (the new path listener). Its `base` is the text as last committed or merged.
- A call whose value equals `base` changes nothing (its own commit's echo, or an unrelated write): pending typing stays pending, so one commit per pause still holds.
- A value other than `base`: commit pending typing (the crdt rebases it, as today for remote changes), read the merged text, set `base` and the buffer to it, report the splices through `on_merge`. A removed field reads as empty.
- So two sessions on one field share it (each sees the other's commits as merges), clearing a draft is a plain `remove` (open sessions go empty), and an undo shows in open sessions. No close, remove, reopen.
- Rename `on_remote` to `on_merge`: what it reports is any change merged into the buffer, local ones included; "remote" would now be wrong. (Tess may prefer another word.)

## API before and after
Gone: `Delivery::Fired`, the `signals` of `Event::Ephemeral` (the branch removes those of `Applied`/`Joined`), signal firing through `on_change`/`on_thing_change`, the port's fired-signal Notify on aspect and thing subscriptions, `TextSession::on_remote`.
New: `PathRef::on_change::<U>`; the port's aspect filter takes a path (`[0, tid, ak, path]`, changed in place).
Renamed: `on_remote` to `on_merge`. `port::SIGNAL_BYTES` keeps its job (held ephemeral signal entries and diagnostics for a slow client) under a name for it, e.g. `PUSH_BYTES`.
Unchanged: `on_change`, `on_thing_change`, `on_grants_change`, `on_status_change`, `on_history`, `on_diagnostic`, `on_dispute`, `Change`, `Origin`, `HistoryEvent`, `Subscription`, the dispatcher.

Callers:
- **libs/chat**: none (`on_event` already uses `on_history`).
- **kit**: `view/sessions.rs` shares one session per field only because of the session bug (its doc says so): back to one session per editor, the reporters and per-editor bookkeeping deleted. Node state re-render: the shell keeps a thing watch per held thing for content, and node state (`ui:*` maps on the window) is read through path listeners per shown node, re-rendering that node. How kit tracks what each node read is kit's design (an app-session task); osis only needs the path listener.
- **app**: `log.rs` Send: `session.commit()` instead of `close_key`, then clear the drafts; no rebuild. `about.rs` Undo and `opener.rs`: drop `sessions.close` and the forced rebuild.
- **cli**: `watch T AK [PATH]` (as `get`); a signal is followed with `history --follow` (new flag; `watch` on a signal key shows only its initial absent).
- Tests naming `Fired`/`on_remote`: `core/osis/tests/it/{api,sync,watch,ephemeral,port,sources}.rs`.

Checklist (notes/api-design.md): (1) generalized `on_change` to the path address `get` already has; (2) signal firing in `on_change` removed in the same change; (3) no new word but `on_merge`, replacing one; (4) nothing internal exposed, no new number; (5) shape: value vs entries is the only split, decided by the contract (initial call and coalescing vs per entry); (6) through a connected node: path filter on the port; offline: local; deleted thing: path reads `None`; `p![]`: the root; (7) notes/api.md Watching, Signals, Text sessions and `lib.rs` examples (the signal example moves to `on_history`) are rewritten in the build.

Numbers (notes/arbitrary-values.md): none added. Cost, stated instead: a write to an aspect costs one path read per path listener on that aspect (O(listeners on the aspect)); a later skip by op path is a performance switch, only if measured.

## Questions for Tess
1. Signals only through `on_history`, ephemeral ones too, with `on_change` on a signal key hearing only its initial absent. Or should the compiler refuse `get`/`on_change` on a signal key (generated signal keys without them)? Leaning: yes, as a follow-up step, since a read that is always `None` is a misuse the compiler can catch.
2. No option to exclude local writes (reasons above). Agree?
3. `on_merge` as the name for a session's "your text changed under you" listener.

## Build steps
Each one worker plus a reviewer, in order; each names its property and its small tests.
1. **Ephemeral signals are entries** (after `signal-fire` merges). Property: every signal write, durable or ephemeral, local or remote, reaches `on_history` as one entry per time it reads otherwise, and `on_change`/`on_thing_change` hear nothing from it. Engine queues ephemeral signal arrivals and own sends into the end-of-transaction history list, carrying the entry; delete `Delivery::Fired`, `Event::Ephemeral.signals`, the port's fired Notify (port history subscriptions carry them, counted against the push bound). Tests: local ephemeral signal, one `Commit` event with `Held(v)` and an empty page; two nodes, the receiver hears it once; thin client hears it through `on_history`; `on_change` on a `+~` key gets only `Initial(None)`; a slow port client past the bound gets `Reread`. Update notes/ephemeral.md Watches, api.md Signals, spec/data-model.md §2 and the `lib.rs` signal example.
2. **Path listeners.** Property: a path listener is called exactly when the value at its path differs after a transaction, from any cause. `PathRef::on_change::<U>`, the port's aspect filter with a path, CLI `watch T AK [PATH]`. Tests: write entry `a` of a map: the `b` listener is not called, `a` once; remove `a`: `None`; delete the thing: `None`; a `set` of the whole map calls only changed entries; an entry changed by a validity flip is called (`Derived`); a mismatching entry reads `None` with `Mismatch`; same through a thin client; count: N listeners on one aspect, one write, one call and N reads (counted, not timed).
3. **Sessions follow every write.** Property: an open session's buffer is the field's value merged with its pending typing, whoever wrote the field; its own commits' echoes neither report nor commit. Session listens at its path, compares with `base`, `on_remote` renamed `on_merge`. Tests: `remove` of the field empties an open session (no close); two sessions on one field typed and committed in turn keep both texts (`two_editors_on_one_field` at the osis level); a session's own commit reports nothing and commits nothing pending (count commits); undo of a committed edit shows in the open session; a remote edit still merges as before.
4. **Callers.** kit sessions back to one per editor (sharing deleted), app Send/Undo/opener without close or forced rebuild, CLI `history --follow`. Property: the app's draft clear and undo work with sessions left open. Tests: kit's existing session tests, the send-clears-draft and undo app tests, rewritten to keep editors open.
5. **Node state granularity** (app session with Tess): kit reads node state through path listeners and re-renders the node whose state changed. Property: one node-state write re-renders one node. Test: count node rebuilds for one `ui:week.0` entry write.
6. **(If Tess agrees with question 1)** generated signal keys without `get`/`on_change`: a compile-fail doc test.
