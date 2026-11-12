# The frontier stop below a purged part may be removable
> Summary: A snapshot's own frontier walk stops below a part held value-less for a purge (`retention::held_purged` in `snapshot::claims`; spec/crdt.md §1, §8), which forces fresh sessions when an own write is purged (`purge::purge_one`). Its reason was covering: a snapshot tracing the part would cover it once the purge fell. `covered_join` now refuses that by itself (a snapshot holding a write of a body not held value-less covers it only past its expiry), so the stop may be a second rule for one property.
> Priority: low
> Tags: engine, retention

## To settle
- Check every other reader of a snapshot's frontier and `Absorbed` (`unseen_by` for memory bodies, `receipt::settled`, demotion frontiers, spec/sync.md §9) for a reason to keep it.
- If none: drop the stop, the fresh session in `purge_one`, the spec lines (crdt.md §1 "or is held value-less for a purge request", §8 `ctr` and `Absorbed` exclusions), and the notes bullet (notes/engine-retention.md Frontier below a purged body).
