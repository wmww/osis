# Opening a store another process holds gives no error of its own
> Summary: `Osis::open` on a store another process (or a node in this one not yet shut down) holds fails as `Error::Storage("... Database already open. Cannot acquire lock.")`, indistinguishable from a corrupt store. kit's startup screen therefore offers start fresh for a store that is merely in use, which would move a working store aside under a running app. Ask: a distinct error (e.g. `Error::InUse`), so the screen says "open elsewhere" and offers no start fresh.
> Priority: normal
> Tags: core-ask, app

- Seen: a second `osis-app` on the same dir; reopening right after dropping the last handle (closing with `Osis::close` avoids that one: kit's `Started::close`).
- Start fresh only renames, so nothing is lost: the other process keeps writing into the moved dir.
- Not string-matching redb's message in kit: it is a storage detail that changes with redb.
