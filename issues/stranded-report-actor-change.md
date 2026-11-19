# A stranded report under a sync ID's earlier actor outlives a newer report
> Summary: `carriers::report_taken` replaces the reports of the new report's actor only (the `Carrier::Report` key orders by actor for `reports_gone`). Once a sync ID's thing changes independent (its actor), a report taken under the old actor keeps carrying its holder keys while the holder stays current on the old actor and the node holds it, beside the newer report: spec/commits.md §4 Pending storage keeps the newest per sync ID, and only while its holder is a current holder of the sync ID's actor.
> Priority: low
> Tags: engine, sync

Bound: one extra report per (sync ID, earlier actor); only an admin's change of the thing's independent makes one, so no stranger grows it. Fix: drop a report whose actor is no longer its sync ID's actor where the actor changes (the closure knows when a thing's independent moves), or index reports by sync ID beside by actor. Test: take a report on S, make S's thing independent, take a newer one; the first's commits go.
