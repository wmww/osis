# commit-cost
- `tools/cpuprof` writes binary paths as given: run with a relative path and `--report` from another directory shows every frame as `??`. Report from the directory it ran in, or pass an absolute binary path.
- Adding a dev-dependency changes the test binary's hash: a probe loop against the old `it-<hash>` path silently measured stale code. Take the path from `cargo test --no-run` each time.
- Per-part work over a whole commit hid behind cheap-looking calls (`put_meta`, `Meta` clones, `parts.iter().find`, `aspects.iter().position`) and two debug checks; cpuprof's filter by frame (`--report FILE N FILTER`) found callers fast once paths were right.
- `LazyHeader::arc()` decodes at once; taking it before checking the record is held made `check_index`'s "no header decoded at open" fail, seen only in node properties (`keep::any_order_keeps_no_more_large`, `order::held_set_decides_plain`), never in the default tests. Clone the `LazyHeader` and deref where the header is needed.
