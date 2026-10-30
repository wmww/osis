# net-cleanup
> Summary: Footguns met on the net-cleanup branch.

- `cargo clippy` does not build the iroh module: a trait import that only iroh.rs tests used broke `clippy-net` after a dedup in quic.rs; run clippy-net after touching transport.
- Reviewer: `tools/gate.sh > log; echo exit $?` in a background task reports the echo, so claudewait showed exit 0 for a failed gate; read the gate log's last line (`== gate passed`).
