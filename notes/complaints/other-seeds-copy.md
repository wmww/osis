# other-seeds-copy
- Hand-rolled xorshift test rngs (crdt-model, roles-model, keys members, osis text, kit list) emit only zeros from seed 0: "set the seed to 0" silently makes a constant stream. Guarded now; any new xorshift must guard too, or use `SeededRng`.
- Zero-argument helpers (`tied::setup()`) make several nodes from internal seeds, so a test that looks single-node is multi-node: a scripted seed pass must treat them as node creators.
- Several crates' `it` binaries share `target/debug/deps/it-*`: `ls -t` picks the wrong crate's binary for `tools/icount`; name the exact hash.
- An icount loop over `--list` output must drop its trailing summary line, or one call runs the whole binary.
- proptest-regressions files (core/crdt: 68 cases; base, host, commit) are pinned failing seeds replayed every run, outside any seed grep of `.rs` files.
