# Finding a sync ID's destroyed actors costs every held holder
> Summary: `Engine::destroyed_upstream` (called by `certificates`, which the facade's own-certificates value per sync ID recomputes whenever what it read moves) checks every actor named as a holder anywhere at the node (`Held::holders`) for a destruction, and `history_certificates` walks each destroyed actor's whole edge history again each time. Each recompute grows with all actors the node knows, not with the sync ID or with the destroyed actors.
> Priority: low
> Tags: engine

- Fix shape: keep the set of destroyed things whose record is kept (journaled with `Held`, rebuilt at open), so the walk costs the destroyed actors only; cache a destroyed actor's history certificates by its held edges (frozen, they change only by a late or fallen write).
- Count it: recomputes at n and 10n holders elsewhere at the node, the sync ID's thing unchanged.
