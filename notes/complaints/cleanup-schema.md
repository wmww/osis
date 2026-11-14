# cleanup-schema
- `tools/dup_windows.py` prints nothing when it finds no copies: an empty output reads like a failed run. A "no repeated windows" line would settle it.
- The `#[deprecated]` probe works well (one clippy run lists every use site, GUI crates need a second run with `-p`), but its raw output is ~1500 lines: aggregate by function name and by `core/<crate>` prefix, excluding the crate's own `src/`, to see the unused or test-only ones.
