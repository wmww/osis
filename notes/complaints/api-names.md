# api-names
- A 1000-site rename over tests hits engine and harness methods of the same name (`World::add_host`, `Engine::knows`, `SyncEngine::host_key`): compile errors show the wrong ones, but only after a full check of each crate's tests. Scoping the script by regex on the receiver saved little.
- `cargo test --workspace` stops at the first failing crate: use `--no-fail-fast` to see everything once.
- `git grep -A` needs its options before the pattern (`git grep -n -A5 pat`).
- notes/client-port.md and notes/api.md hold whole design paragraphs on one line: a word sweep is safe, a real rewrite means reading 200-character-wide diffs.
- Review: a bulk "host" to "peer" over comments turned a verb too ("a node that peers"): sweep nouns only. A test harness's `Net::settle(1)` panics at one message rather than stepping: `round()` steps.
