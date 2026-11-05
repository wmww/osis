# Complaints: no-server-audit
> Summary: Footguns met auditing P2P with no hosts.
- `InProcess` dials `peer://` by key and `World` drops peer dials, so tier 1 can't show a peer not being found; the task's "World with no hubs" route doesn't work for P2P at all. Real answers needed `cargo test-net` with iroh.
- `cargo test-net -p X` still runs the whole workspace: the alias has `--workspace`. A filter is what narrows it.
- `driver_lan_loop_localhost` failed once in 5 runs (commit never applied in its 30 s guard), then passed alone: a flake that fails `cargo test-net` fast and hides later crates' tests unless `--no-fail-fast`.
- A probe that mixes a rotated key with the next check fails for the wrong reason: two of mine did, until I checked the key first.
