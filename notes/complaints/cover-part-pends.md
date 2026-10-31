# cover-part-pends
> Summary: Workflow notes from the atomic-wait-by-listing change.

- `tools/spec_map.py --check` prints "wrote notes/testing-map.md" though it changed nothing; unclear whether `--check` writes.
- The node test constants `REG`/`TAGS` are typed `Aspect<Value>`, while engine calls take `Ak`: tests mix `ak("/t/tags")` and `&TAGS`; a compile round each time.
- Reviewer: copying the osis-node test binary for oracles means probing 13 `target/debug/deps/it-*` for the test name; `cargo test --no-run` does not say which crate each is.
