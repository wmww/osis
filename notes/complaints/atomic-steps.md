# atomic-steps
- Box at load 50-58 throughout: a plain `cargo build -p osis-engine` passed the 120 s tool timeout; run builds in the background from the start under load.
- notes/engine.md and notes/node-sync-work-sets.md cited a debug assertion in `Engine::run` ("no index changed without `touch`") that does not exist; removed.
- Review: `Core::schemas` (plain map) kept a failed transaction's registration while its store record rolled back, so the next registration skipped the write; found only by listing every `Core` field's rollback class. A new field must now be classified to compile.
