# Complaints: stale-read
> Summary: snags met finding why a reader kept a stale value (a taken deposit never opened).

- The shrink stopped at 22 of 30 steps after 111 candidates (cap) and a second shrink found nothing more: each candidate is a full 7 s world, so a 20+ step differential script shrinks for about 10 min a round.
- The quiet check `World::parks` skips entries with no commit known (never opened), which was exactly this bug: a stored entry never handed to the engine. Diagnosis needed a scratch `open_entry` of every store entry at the end and a temporary trace note in `store::open_entry`; an env-gated "entries of a read S that never opened" dump would have shown it at once.
- `Lie::Declare` only changes how a node opens sync IDs from then on: set on a connection already open it does nothing, so a test must set it before the grant.
- A fix that changes timing moves every world of a scratch script: the 50-world rate of the shrunk script after the fix met another class on world 32 (issues/differential-gone-alike-after-uncover.md); telling a new failure from a moved world took a pre-fix binary (`tools/bin-at`) and a probe of both.
