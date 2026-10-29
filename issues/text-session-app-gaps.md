# Text sessions: caret mapping and resurrection after delete
> Summary: Two gaps the notes app hit in `TextSession`: `on_remote` reports only the merged text (no edits), so a UI cannot keep the caret across a remote edit; a session dropped after its thing was deleted commits its pending text and recreates the thing (also after a remote delete: an invisible orphan body). The app diffs whole widget text into splices because of the first.
> Tags: core-ask, api, owner-call

Owner: to be handled later on the core side; app work lives with both meanwhile.

Repro: app/ (notes app, notes/app.md Prototype); for the second, in a test: `edit_text(t, BODY)`, `insert`, `write_with(|w| w.delete(t))`, drop the session: `get(t, BODY)` is the typed text again.

- **Caret**: notes/api.md says remote edits are reported through `on_remote(|edits|)` so the UI can map cursors; the code passes `&str` (the merged text). The app resets the widget text and the caret jumps to the end. Ask: deliver the edits (or a char-index map old -> new) with the merged text.
- **Resurrection**: `delete` removes every aspect; a session on the thing still commits on drop (and on idle), writing the pending text into a deleted thing, which recreates it (notes/api.md: a later write recreates the thing). Workaround: the app drops its sessions before deleting. Ask: decide whether a session whose thing was deleted (locally or remotely) after it opened drops its pending edits (and reports it through `on_remote` or a diagnostic) or keeps today's behaviour; owner-call because "a later write recreates" is a deliberate rule and a remote delete racing a local pause is the same case.
