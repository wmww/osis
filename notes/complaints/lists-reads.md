# lists-reads
- A devices actor's closure is D's own `group.0` items (and what D is key home of), not the synced group's: the synced group lists D as a subgroup, so filing a thing in the synced group never puts it in D's closure. Cost a probe round.
- `Closure` (`Groups::closure_of`) has no `Debug`; printing it needs `.iter().collect::<Vec<_>>()`.
