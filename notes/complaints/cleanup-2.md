# cleanup-2
- `tools/mutate.py` runs the built test binaries outside cargo, so proptests ran 256 cases and a caught mutant wrote `core/crdt/proptest-regressions/` into the tree. Set `PROPTEST_CASES=32 PROPTEST_DISABLE_FAILURE_PERSISTENCE=1` for it (or have mutate.py set them as `.cargo/config.toml` does).
- `tools/deprecated_probe.py --dead` lists items used only by non-default members as dead: osis-proto `Msg::code`/`answered` (osis-vectors), osis-schema `Path::steps` (osis-kit, roles-model). Grep before deleting, as the brief says; the probe could include osis-vectors in its clippy.
- The fuzz crate (core/test/fuzz) is built by no check: `fuzz_targets/box.rs` named `sealed_from_value` for a long while after 827f962e9 deleted it. Fixed by name here, still unbuilt.
