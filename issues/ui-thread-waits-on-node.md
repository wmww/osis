# The UI thread waits on a busy node
> Summary: kit renders on the UI thread and every osis read there takes the node lock, so a re-render waits for whatever holds it (a sync apply, a commit). Text sessions keep keystrokes off the node lock (a save holds only its own save lock across the node call), but a merge on a `Pump` dispatcher (the UI thread's `settle`) and an inline save without a runtime still run node calls there. Decide what the UI thread may wait on.
> Priority: normal
> Tags: kit, app, osis

- Where it waits: kit render reads (`Data` reads through `Osis`), `settle` running a session's merge (it commits pending typing and reads the merged text), `TextSession::splice` saving inline after a pause when no runtime arms the idle timer.
- Not waiting: `splice`/`text` during a save in flight (test `text::text_keystroke_does_not_wait_for_a_save`).
