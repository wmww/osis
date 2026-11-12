# eph-large
- `big_notes` made values of `len` bytes only for single-digit indices (`"10".repeat(len)` is twice as long): once values chunk above 128 KiB, some test values silently crossed the threshold and a test "leaked" pages that were really chunk trees. Fixed to exact lengths.
- Paged tests sized "past a blob" with a few huge values stopped testing paging once values chunk; every paging test had to be resized to many inline values (`paged_notes`). A test named for a mechanism should assert it (a page count) rather than rely on sizes.
- A background command redirecting into a scratch subdirectory created in a parallel call failed (the directory did not exist yet): create it first, in its own call.
- Review: `cargo test -p a -p b filter1 filter2` is refused (one TESTNAME); pass several filters after `--`.
