# An aspect whose snapshot root tables pass MAX_BLOB never compacts
> Summary: a snapshot's root tables (`Sources`, `Commits`, `Absorbed`, `Frontiers`) are inline in its root blob; past `MAX_BLOB` (8 MiB) the snapshot cannot be written, so that aspect is never compacted on any node and every body of it, dead writes included, is kept forever. Any writer reaches it with about 10^6 session-form or 78,000 commit-form commits whose writes survive; honest growth too.
> Priority: normal
> Tags: security, crdt, engine

- Sizes (issues/durable-decode-bound.md, Step 6): per surviving commit about 8 B in session form, 107 B in commit form.
- Effect: `Engine::compactions` reports it (`OwnWriteFailed`) and keeps the aspect's estimate, so it is weighed and fails again at each new body: a full state encode per body of that aspect. Nothing else stops; but every later overwrite on the aspect is a body kept forever on every holder, so storage grows with writes, not with state.
- Same class as link pages nesting deeper than a fixed level: a format limit a writer can reach. Fix by the same move: root tables paged as `[Link+]` with the link-level rule (spec/wire.md §6), decoded first into compact tables (Step 6 of issues/durable-decode-bound.md).
