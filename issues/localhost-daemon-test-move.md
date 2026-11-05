# daemon_clients_localhost still runs `osis move`
> Summary: The ignored osis-cli test `localhost::daemon_clients_localhost` fails since remove-moves (item 270): it calls `osis move <thing> <group>` (cli/tests/it/localhost.rs, "moves, a bundle, ..."), a subcommand that no longer exists; its doc comment still lists `move`. Drop the move step and the mention. Remnant left because the test is `#[ignore]` (localhost, tier 2).
> Tags: cli, tests

Repro: `cargo test -p osis-cli --test it -- --ignored --exact localhost::daemon_clients_localhost`: `error: unrecognized subcommand 'move'`. Found in periodic run 15 (whole tier-2 set).
