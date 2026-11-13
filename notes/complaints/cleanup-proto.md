# cleanup-proto
> Summary: proto and transport had little dead code left; dead_pub's allow-list hid two dead items, and an unused helper hid behind its own tests. Most cuts were merges of two copies of one rule.

- `tools/dead_pub_allow.txt` kept `drop_claim_set` ("test hook") and `close_gracefully` ("deferred: 3h2 decides") long after nothing called the first and node sync settled without the second. An allow-list reason that names a pending decision should be rechecked when that step lands.
- `dead_pub.py` cannot see a pub fn whose only caller is its own test (`manage::connect`, reached only by `tests/it/manage.rs`). Grepping each pub fn's callers outside its crate's src and tests found it.
- `cargo test -p osis-proto -p osis-transport -p osis-host -p osis-node -p osis` took about 3 minutes warm, well under its expected cost.
- The networking check fails `sources::thin_client_over_quic` on main too (issues/thin-client-quic-rotation.md). Without `--no-fail-fast` that first failing binary stops the run before the transport and node binaries; the command in notes/coordination.md should carry the flag.
- Review: after `tools/bin-at`, `target/debug/deps/it-*` holds the REV build until the next `cargo test --no-run`; copy the branch binary out before building the old one, or comparisons run main twice.
