# scale-counts
- `RUSTC_BOOTSTRAP=1` on a `cargo` command (to get `--report-time`) changes rustc's fingerprint: the whole tree rebuilt twice (11 min each). Put it only on the test binary (`RUSTC_BOOTSTRAP=1 target/debug/deps/it-* -Z unstable-options --report-time`), never on cargo.
- `Engine::open` with a fixed seeded rng in a test draws the same session nonce every open; a second session's commit then fails with `Permission` (the old `scale.rs` `Reopen`). `LocalPeer::restart` mixes the open count into the seed; use it.
- Store reads (`MemoryBackend::io().reads`) are polluted in debug builds by `check_rebuilt` and `recheck` (sampled, so a count jumps at powers of four). Count reads with cost spans (paused during debug checks); store bytes written are clean.
- A paged text needs about 70k chars, so 10n is 700k: 11 s to write in debug. `text_edits_are_flat` is tier 2 for that.
