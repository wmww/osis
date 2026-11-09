# Derived epoch establishment is order-dependent
> Summary: Whether a thing's derived epoch is marked established (`Core::adopt_derived`) depends on whether its first admin's epoch was established when the thing's `secrets.0` ingested, so an incremental index and a rebuilt one can differ.
> Priority: normal
> Tags: engine, tests

`adopt_derived` runs only at ingest of the thing's own secrets. A node that gets the first admin's establishment later leaves the thing's epoch unestablished while a rebuild from the commits marks it `Derived` (`Engine` debug check "rebuilt from the commit records, the index Table(\"secrets\")").

Repro on the net-role-sync branch's parent: a group item with a co-admin grant, granted to a second group, a co-admin syncing it (the deleted test `sync::a_sync_by_a_co_admin_who_never_met_the_group_reaches_its_readers`, git history). Re-adopting at the first admin's secrets ingest did not fix it: establishment also comes from applied commits (`Core::names_held`), so the fix needs a hook there or computing the adoption at read (`own_epochs`).
