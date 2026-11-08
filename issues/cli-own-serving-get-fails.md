# CLI localhost: Bob cannot read a thing after redeeming a link on Alice's own serving node
> Summary: `localhost::own_serving_node_localhost` (osis-cli, tier 2) fails every run: after `link redeem` returns the group, Bob's `get <thing> t:x.0` exits non-zero with empty stderr. Fails alone on e3cdd005f and 8f3cd8d05 (11-19 s), so not load.
> Priority: normal
> Tags: cli, node-sync, tests

Replay: `cargo test -p osis-cli --test it -- --ignored --exact localhost::own_serving_node_localhost`. The failing line is the `get` right after `link redeem` (cli/tests/it/localhost.rs, `own_serving_node_localhost`). Not looked into: whether the redeem returns before the thing synced (a wait missing in the CLI or the test) or the own-serving peer never serves the group's label to Bob. Empty stderr on a failing command is a CLI bug either way.
