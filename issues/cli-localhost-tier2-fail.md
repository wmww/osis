# Two CLI localhost tier-2 tests fail on main
> Summary: `cargo test -p osis-cli --test it -- --ignored localhost::`: `daemon_clients_localhost` fails with `store in use by pid N` on `create` (the invocation does not reach the daemon's socket) and `own_host_device_localhost` with `invalid: keys` on `link redeem`, every run, on main a7ea8a3f as on the client-actors branch. `two_people_three_devices_one_host_localhost` passes. Neither is in the notes/coordination.md networking check, so nothing runs them per branch.
> Tags: cli, tests
