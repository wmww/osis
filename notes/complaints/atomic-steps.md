# atomic-steps
- Box at load 50-58 throughout: a plain `cargo build -p osis-engine` passed the 120 s tool timeout; run builds in the background from the start under load.
- notes/engine.md and notes/node-sync-work-sets.md cited a debug assertion in `Engine::run` ("no index changed without `touch`") that does not exist; removed.
