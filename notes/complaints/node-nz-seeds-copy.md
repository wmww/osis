# node-nz-seeds-copy
- `net(n, 0)` gives peers seeds 0..n-1, so a second `net(1, 0)` in the same test is peer 0 again (same identity, keys, account): it compiles and often still passes. A second node needs seeds apart (`net(1, 1)`), and a pushed `Peer::new` one outside 0..n-1.
- `Net::restart(n, seed)` reopens on `SeededRng(seed)` as given (no restart count mixed in, unlike `Peer::restart`): a restart seed equal to the node's creation seed or an earlier restart replays its rng stream. Restart and rotation rng numbers are must-differ values, not seeds to zero.
- `order::with_syncs` picked the sync mode from `seed % 3`: zeroing a named `check`'s seed silently dropped its late syncs (only a probe of the played mode showed it). `Cfg::late` names it now.
- A probe env var named `OSIS_*` fails the test run (testenv rejects unknown `OSIS_` variables); `eprintln` probes need `--nocapture`.
- `cargo test ... sync::` also runs `shred_sync::` (a substring filter); module totals for `sync` include it.
