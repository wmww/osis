# departure-cover
> Summary: Footguns met on the departure-cover branch.

- A python edit script that re-reads a file it has just opened for writing (`open(p,'w').write(open(p).read())`) truncates it; spec/crypto.md went empty and was restored from the wip commit. Wip-commit before scripted edits too, not only before probes.
- A TLC loop piped through `grep | head -N` kills the run by SIGPIPE after N lines: write each log to a file and grep that.
- The `.osis` schema has no `bytes` type (it is `blob`); the parse failure surfaced only as "node.0 is not declared by its schema" from every engine test.
- `cargo test -p osis-schema` with a failing proptest leaves `core/schema/tests/proptest-regressions/` untracked.
- `osis` `sync_basics::polling_sync_now_costs_nothing_and_holds_nothing_back` fails on any wire change that shifts commit IDs: a relay of another node's blob lands at `RELAY_MIN_MS` + hash(id) % 25 s, and the test's 6 s window hit one. Found by bisecting three fixes and building main's binary twice (`tools/bin-at --patch` with a debug print was the tool that worked). The test now lets relays settle first.
- `cargo test --workspace` stops at the first failing crate: run tier 1 with `--no-fail-fast` or one failure hides the others (three crates failed here, one at a time).
- A new dependency of a core crate (blake3 in osis-keys) leaves libs/kit/Cargo.lock stale; the gate's last step (`cargo check --locked` in libs/kit) fails after 12 min of passing steps. `cargo metadata --offline` in libs/kit updates it.
