# keel-unstamped
- `eprintln!` in a probe inside passing tests is swallowed by libtest's capture: write probes to a file.
- `std::backtrace` in debug test builds resolves few frames (debuginfo is limited): `#[track_caller]` + `Location::caller()` located the sites instead.
- A whole `cargo test -p osis-sync --test it` run while editing sources picks up half-edited crates; run tests only between edits.
