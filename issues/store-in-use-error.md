# Start fresh is offered where the store is fine
> Summary: kit's startup error screen (libs/kit/src/render/start.rs) offers Start fresh for every startup failure, so it would move a healthy store aside: when another process holds the store (`Osis::open` fails as `Error::Storage("... Database already open. Cannot acquire lock.")`, indistinguishable from a corrupt store) and when a later step fails (the app's data setup: desktop `--demo`, `--theme`; `Ui::new`). Offer it only when the store itself cannot be read; a store in use needs an error of its own.
> Priority: normal
> Tags: osis, app

- A store in use: a second `osis-app` on the same dir (desktop only: Android's shell closes an older view's store before opening), or reopening right after dropping the last handle (`Osis::close`, kit's `Started::close`, avoids that one). Ask of osis: a distinct error (e.g. `Error::InUse`), so the screen says "open elsewhere" and offers no Start fresh. Not string-matching redb's message in kit: it changes with redb (the CLI matches it today: issues/cli-daemon-errors.md).
- Start fresh only renames, so nothing is lost: the other process keeps writing into the moved dir; the user sees an empty app.
- A store opened before a later step fails is dropped without `close`, staying locked briefly.
