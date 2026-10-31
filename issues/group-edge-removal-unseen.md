# A group's members do not learn an explicit removal of the group's edge
> Summary: when T's admin explicitly removes (demotes) group G's edge on T, G's admins and members keep G's edge in their roster of T (and `reach`) forever: the removal goes under T's labels and G's inbox, but G's members apply neither. They read nothing new of T (the rotation leaves them out), so it is a stale view, not a leak.
> Tags: permissions, sync

Repro: core/osis/tests/it/tied.rs `share_into_unplace_and_stale_placement` (Bob demotes the tag's edge on his card; Alice, the tag's admin, still lists it). The same with a plain `grant`/`demote`, so it predates tied grants.

spec/permissions.md §2 requires the inbox delivery to G "so G's admins know what G is a member of and erase what G lost". Find out why the inbox copy (or a label copy) does not apply at G's admin; a self-removal of G's edge is placed whole under the labels holding G (`demote_in`, `Delivery::Deposit`) and does reach them, which may be the shape to reuse for explicit removals.
