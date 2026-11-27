# Strict model violation: an admin's plant splits a sync-only node's storage
> Summary: After an admin's plant (fa7df8ad0), a node reading none of Y's role commits (sync only) still counts Y independent, so it syncs Y under a sync ID nobody else writes. Reads stay right (held-model `independent.rs`: "it splits storage, not reads"), but that node keeps rows nobody else can attribute. Hostile admin only.
> Priority: low
> Tags: engine, sync

Test showing it: `an_admins_plant_splits_no_reader`. Accepted limit until a rule lets a sync-only node judge independence like a reader.
