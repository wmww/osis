# kit's splice races a session merge
> Summary: `kit::edit::splice` reads `TextSession::text()`, picks a range against it, then calls `splice(range)`; a merge on the dispatcher thread can replace the buffer between the two, so the keystroke lands at a stale index (wrong place, or deleting merged chars). Needs an atomic edit against the text the widget showed.
> Priority: normal
> Tags: kit, osis

- The window is one keystroke's diff wide; with `Dispatcher::Thread` (kit's default) it is open. The widget then shows the session's text, so the damage is visible but already committed at the next save.
- Shape of a fix: a `TextSession` call that takes the widget's `shown -> new` and places it under the session's state lock (kit's placement rule moving into osis), or a `splice` that fails when the buffer is not the text it was computed against, retried by kit. Either is an osis API change (notes/api-design.md).
- The deterministic interleaving (merge taken after the keystroke) is covered: app `views::typing_before_a_merge_shows_keeps_both`.
