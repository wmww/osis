# crdt-expiry-seeds
- A seed sweep that runs `target/debug/deps/osis_crdt-<hash>` in place gets the binary swapped mid-run by any cargo build in the worktree (here `cargo clippy --all-targets`). Copy the binary to scratch first.
- I piped a parallel sweep's `FAIL <seed>` lines through `tail`, which showed only the last few and looked like failures clustered at the end of the range. Write sweep output to a file and count it.
- `tools/heavy` flagged a 40k-seed sweep at -P 32 (CPU 1.8x, wall 1.3x its limits, load 49). Split long sweeps.
- Review: main moved by about 20 commits during the gate, so the gate's NEW sim `ephemeral` failure was already KNOWN on the new main (its line landed meanwhile). Checking a failure "on main" means at the branch's base and at the current main.
- Review: `OSIS_CRDT_SEED` reaches only `#[ignore]` properties in the gate; the default crdt tests run at committed seeds, so seed-rate failures of non-property tests (`sweep_laws` ~9%, `forged_entry_copies` ~75%) never show in a gate and their known lines only document.
