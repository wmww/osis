//! The sans-I/O sync engine and its tokio driver (plans/node-sync.md; notes/architecture.md §2):
//! `SyncEngine::handle(Event) -> Vec<Action>` over osis-proto sessions, labeling and flows.
//! Feeds the engine with `Engine::ingest`, `set_syncing`, `set_clock_offset`, `tick`.
