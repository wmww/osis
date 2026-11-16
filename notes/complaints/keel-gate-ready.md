# keel-gate-ready
- `cargo test --workspace --no-run` fails on main: osis-kit uses osis API the demolition removed (`Member`, `group`, `home`, `members`, `Status::groups`). Listing tests needs the core-only `cargo test --no-run`. The full gate's GUI lint will fail the same way until a lane fixes kit.
- `code_refs` passes a name that survives only in a comment, so notes citing demolished tests by bare name pass policy; checking against `--list` of the built binaries was the only reliable way.
- Parsing `Executable unittests src/lib.rs (path)` by field order silently dropped every lib unit-test binary on the first try; take the path in parentheses.
