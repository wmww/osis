# Purge harness: held-model and engine judge a write's validity apart since addenda
> Summary: `order::arrival_order_purge_large_spec_commits_5` seed 316669818817 (as made) fails on main from the addenda merge (1a829fe51) on: held-model says a `t:reg.0` write is invalid, the node valid. Likely the model has no addenda (a writer vouching for a removed holder's edit); not triaged.
> Priority: normal
> Tags: tests, engine, permissions

- Replay: `OSIS_ORDER_SEED=316669818817 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --include-ignored --exact order::arrival_order_purge_large_spec_commits_5` (under a second). Fails alike on main 3a875fb9b and on retention-1.
- First difference: validity of commit #2 on `t:reg.0`, model `Some(false)`, node `Some(true)`, at the node holding all 69 commits as made. The harness's `Cfg` says `addenda: false`; check whether the node still applies addenda it receives, and whether the model needs them (core/test/held-model AMBIGUITIES.md) or the adapter should leave such commits out of scope.
