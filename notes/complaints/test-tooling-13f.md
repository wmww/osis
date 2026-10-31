# test-tooling-13f
> Summary: small footguns met while fixing test tooling.

- osis-sim is a library crate under the workspace's `clippy::panic = deny`, so a harness panic in `world.rs` needs the module-level allow (now on `pub mod world`); tier 1 passed and only clippy caught it.
- The sim World's doc said the osis tests "cannot depend on this crate" while seven osis test files already did: the duplicate World lived on for no reason.
- Engine diagnostics (`Engine::report`) reach only event subscribers, not `SyncEngine::take_diagnostics`, so the four per-file `diags`/`trace` helpers in node tests never showed refusals like `EphemeralRefused`.
