# net-cleanup
> Summary: Footguns met on the net-cleanup branch.

- `cargo clippy` does not build the iroh module: a trait import that only iroh.rs tests used broke `clippy-net` after a dedup in quic.rs; run clippy-net after touching transport.
