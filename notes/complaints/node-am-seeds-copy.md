# node-am-seeds-copy
> Summary: footguns met zeroing seeds and caching setups in osis-node tests a-m.

- `cargo test` name filters are substrings: `judgment::` also runs `net_judgment::`, so per-module icount totals overlap; measure per test with `--exact` for exact numbers.
- Restart seeds are identities, not world seeds: `Net::restart(n, s)` with `s` equal to a node's creation seed or another restart's replays an rng stream (`inbox_life::declined_invite_forgotten` restarts node b with its own creation seed 2). `Net::restart` could derive its seed from the node and its life count, as `Peer::restart` does, and drop the parameter (callers span both halves of `tests/it`).
- A world cached per property seed (`common::net(4, 1000 + seed)`) keeps one world per seed for the process; such loops build with `LocalPeer::new` directly.
