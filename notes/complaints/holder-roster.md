# holder-roster
- The task names grant copies, but grant-copies had not landed in sync-rebuild; its sync-holder copy (a `secrets.0` part) needs the same fix once it does.
- `core/test/fuzz/fuzz_targets/inbox.rs` did not compile (`.ok()` on a `Value`); the fuzz crate is outside the workspace, so nothing catches it.
- `osis_crypto::Domain` strings differ from spec/crypto.md §2 (`"osis v1 label register"`/`"osis v1 upload"` vs `"osis v1 sync step"`/`"osis v1 stamp"`).
