# Finding a label's ended actors costs every held holder per pass
> Summary: `Engine::ended_upstream` (called by `certificates` on every pass of every label) checks every actor named as a holder anywhere at the node (`Held::holders`) for an ending, and `history_certificates` walks each ended actor's whole edge history again every pass. Per-pass cost grows with all actors the node knows, not with the label or with the ended actors.
> Priority: low
> Tags: engine, node-sync

- Fix shape: keep the set of ended things whose record is kept (journaled with `Held`, rebuilt at open), so the walk costs the ended actors only; cache an ended actor's history certificates by its held edges (frozen, they change only by a late or fallen write).
- Count it: passes at n and 10n holders elsewhere at the node, the label unchanged.
