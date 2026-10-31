# Sync pass records outlive the connection they describe
> Summary: `SyncEngine::passes` (core/node/src/sync/deliver.rs) keeps each (server, label) pass record across a disconnect; it is trimmed only for removed labels (deliver.rs:81). Re-seal and until-link decisions that ask "has a full pass happened since X" (deliver.rs ~326, ~361) can count a pass from before the node went offline. Unverified whether any decision is then wrong (a stale pass may still be a correct lower bound). Low.
> Tags: node, sync

Found by the until-link worker (watchdog 13e). First check: what each reader of `passes` assumes about the record (a pass at time t, or a pass on the live connection), then either clear on disconnect or document why a past pass suffices.
