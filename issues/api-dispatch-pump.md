# Callbacks only on the dispatcher thread
> Summary: Watch callbacks run on osis's dispatcher thread, so every change crosses threads (kit's `marshal` mailbox plus a winit user event) before a UI can touch widgets. Ask: a mode where the app pumps the dispatcher on its own thread.
> Tags: core-ask, api

Ask (notes/app.md State in osis): e.g. `Config.dispatch = Manual`, `db.dispatch_pending()` and a wake callback. Not blocking.
