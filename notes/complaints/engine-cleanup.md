# engine-cleanup
- Grouping `Core`'s journaled fields into `Core::ix` renamed about 500 field accesses in 34 files (retention/deaths.rs and node sync included): concurrent branches touching those lines conflict. Redo is mechanical: perl `s/\bcore\.(field)\b/core.ix.$1/`, then insert `ix.` at each E0609 span from `cargo build --message-format=json`.
- A store write fault (`Faults::at`) leaves the `Store` broken (`Store(Broken)`) until reopened; a test that retries after a fault must `Peer::restart`.
- Release A/B timing at load 15-20: copy the two `target/release/deps/it-*` binaries and run them side by side, the only way the numbers were comparable.
- Review: the rebase onto sync-cleanup had no textual conflict, but main's new test code called the removed `reload_index`; only the build found it. A removed `#[doc(hidden)]` API conflicts silently with concurrent branches.
- Review: a store fault (`Faults::at`) needs a reopen afterwards, and a reopen drops in-memory-only state (`hint_candidates`), so a store-fault test cannot show that such state survives a failed transaction; it took an error-returning `Engine::run` closure.
