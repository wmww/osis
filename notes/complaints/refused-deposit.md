# Complaints: refused-deposit
> Summary: the issue's direction (keep a verdict in held) pointed away from the cause, which was the memo layer counting a trial's own undone writes; `Effects` causes name a container but not whether the moved read came from the settle's own rollback.

- `Effects` causes (`inbox: held <- index: commits`) looked like unrelated writes moving the judge; they were the judge's own rolled-back ingest re-stamping what it read. A cause flavour "moved by a write inside its own settle" would have said so at once.
- The commits index and the held set are journaled but have their own `Stamps` fields (not `JMap`s): marking "the journaled containers" missed them first; grep `impl Journaled for` to find them all.
