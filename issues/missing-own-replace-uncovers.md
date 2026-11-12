# An own replace gone missing at a purge's fall uncovers nothing
> Summary: A whole replace held as its leftover becomes missing when its purge falls (`retention::unstrip`, via `rejudge_purges`), so it stops being an own replace (`Indexes::own_replaces`), but nothing re-judges the bodies dropped under it (`retention::uncover`). An earlier body dropped as covered by it and one other own replace stays dropped, where spec/commits.md §5 Own replaces says it is missing again (and fetched) while fewer than two own replaces are held.
> Priority: low
> Tags: engine

`drop_part_for` calls `uncover` when an own cover drops other than as covered; `unstrip` makes the part missing without that call. Values are unaffected (the remaining later own replace replaces the earlier body whole); what differs is must-hold and fetching of the earlier body, against a node holding the same commits that never saw the fall. Until a copy of the replace joins (it may never come if right holders deleted it at hosts after the purge).

Likely fix: in `unstrip`, when the part was a whole replace (`Meta::whole` before the change), `uncover` the aspect before the rebuild, as `drop_part_for` does. Needs a test: W writes C0 then two whole replaces C2, C3; C0 out of history, dropped as covered; an admin purges C2; the admin's removal (not listing the purge) makes it fall; C0 is then missing at this node, as at a node that only ever held C0, C3 and C2 missing.
