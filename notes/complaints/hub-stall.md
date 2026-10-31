# hub-stall
- `cargo test-net -- --ignored ...` took ~200 s here (notes/build.md says ~20 s): mostly the networking build after many transport/server edits, not the tests (longest test result 8 s).
- core/server tests' `World::connect` overflows its `0xe0 + c as u8` key past 31 clients (panic, not a clear error).
- reviewer: `MemoryBackend::sync` could never fail, so the hub's failed-sync path had no test; added `Faults::fail_syncs`.
