# review test-tooling-13f
> Summary: reviewer gate slow under load.

- Gate 492 s (expected ~90): `cargo test --workspace` 315 s and the 5-seed sweep 118 s at load 17-29 from other work, after a 20-seed sweep (735 s) in the same worktree.
