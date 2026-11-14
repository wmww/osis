# dogfood-prep
- On sync-rebuild every `osis serve` failed at once (the startup `peer://` listener had no bind address; the socket listen relistened it): no test ran a real-runtime listen. Added `runtime::two_nodes_of_one_host_listen_spec_sync_transport_3`.
- No test ran two nodes syncing over real sockets, and sync emits no diagnostics: a dead dial-list address hiding the configured `--dial` took strace to find (issues/sync-diagnostics.md).
- Many CLI commands are `Unsupported` through a daemon, so probing a running store meant killing and restarting it each time.
