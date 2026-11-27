# The UI thread waits on a busy node
> Summary: kit renders on the UI thread and every osis read there takes the node lock, so a re-render waits for whatever holds it (a sync apply, a commit). Text sessions keep keystrokes off the node lock (a save holds only its own save lock across the node call), but a merge on a `Pump` dispatcher (the UI thread's `settle`) and an inline save without a runtime still run node calls there. Decide what the UI thread may wait on.
> Priority: normal
> Tags: kit, app, osis

- Where it waits: kit render reads (`Data` reads through `Osis`), `settle` running a session's merge (it commits pending typing and reads the merged text), `TextSession::edit` saving inline after a pause when no runtime arms the idle timer.
- Not waiting: `splice`/`text` during a save in flight (test `text::text_keystroke_does_not_wait_for_a_save`).

## Options (study, no build)
One node lock covers reads and applies: every engine read needs exclusive access (it pulls pages into the engine's cache inside its own store transaction, `engine/read.rs` `get_at_within`), a sync step holds the lock until every module settles (`Osis::step` → `Node::handle`), and `Pump::step` reads each listener's value under it.
1. **Reads from the last committed state** (copy-on-write in-memory state, a read-only store view per snapshot): a read never waits on a write, no public API change; an engine redesign. The only shape where the wait cannot happen by construction. Chosen direction (Sheave): its own structural job once the opening rewrite (opening by entries, spec/sync-ids.md §3) lands.
2. Tracked reads answer from what the listener last saw: first reads still wait, values held twice, against notes/api.md Watching (digests only). Rejected.
3. Sync releases the lock between settle rounds: shorter waits, not none. An interim step only if responsiveness matters before 1.
