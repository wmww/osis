# sync-api complaints
> Summary: Snags met wiring the new sync into the osis API.

- The engine facade on the integration branch is all `NotBuilt` (it lives on branch sync-facade), so no two-node behaviour of the API can pass yet: the end-to-end tests are written and `#[ignore]`d naming that. Merging the facade before the integration step would have let the integration test what it wires.
- The coordinator's rebase hint (`--onto sync-rebuild 22f5476b1`) assumed a branch started at sync-rebuild; one started at a module branch (sync-status) needs that branch's tip as the upstream.
- A status listener read at dispatch time cannot show a connection that came and went within one `run`: tests observe the fabric (`ManualNet::ups`) instead.
