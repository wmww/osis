# parsed-keys
> Summary: complaints from the parsed-keys branch.

- No valgrind on this box: caller attribution needs tools/cpuprof samples, a few hundred per median test, so shares under 1% are noise. A small script that counts caller chains above a frame (what `callgrind_annotate --tree=caller` gives) would belong in tools/cpuprof_report.py.
- `cargo test --workspace --no-run` builds the GUI too (minutes); for a core API change `cargo test --no-run` (default members) is the right check.
