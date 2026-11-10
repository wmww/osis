# purge-resnap
- `net.blocked.insert((c, host))` blocks only c's host link: c still syncs with its group's peers directly, so a "never held" test node held the write anyway and the test passed with the fix disabled. Use `net.set_online(c, false)`.
- `t:reg.0`'s default retention keeps history forever, so a purged write's header stays as a lasting header and a node that never held the body still reads the purge right: another way such a test passes with the fix off. Give the purged write a bounded retention.
- A purge committed by a node that was offline can stamp before a write it names (HLC behind): `net.advance` first, or the request names nothing.
- Review: `snapshots_on` let `addenda.0` through (admin-purgeable, never compacted), so a purge naming it had every writer try a snapshot the engine refuses (a diag each); the snapshot-permitting set lives in two places (`Engine::snapshot`'s refusals, node-sync's `snapshots_on`).
- The worker ran only osis-node tests: the re-snapshot shows in the public `writes` listing, so osis (`listing::`, `port_clients::`) and osis-cli purge tests fail. Behaviour visible through the API needs the osis and cli crates' tests too.
- Review: the main checkout's `main` was behind `origin/main`, so `git rebase main` was a silent no-op; rebase onto `origin/main` after a fetch.
