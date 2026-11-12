# Finding a label's destroyed actors costs every held holder per pass
> Summary: `Engine::destroyed_upstream` (called by `certificates` on every pass of every label) checks every actor named as a holder anywhere at the node (`Held::holders`) for a destruction, and `history_certificates` walks each destroyed actor's whole edge history again every pass. Per-pass cost grows with all actors the node knows, not with the label or with the destroyed actors.
> Priority: low
> Tags: engine, node-sync

- Fix shape: keep the set of destroyed things whose record is kept (journaled with `Held`, rebuilt at open), so the walk costs the destroyed actors only; cache a destroyed actor's history certificates by its held edges (frozen, they change only by a late or fallen write).
- Count it: passes at n and 10n holders elsewhere at the node, the label unchanged.
