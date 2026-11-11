# test-profile-3
- `tools/cpuprof` records frames by the binary path as given: run with a relative path and a later report from another directory names every frame `??` (the filter then matches nothing, silently); rebuild the binary and a report symbolizes old samples against the new one, garbage that looks plausible. Copy the binary aside before rebuilding, and rewrite the sample file's paths to the copy.
- `tools/cpuprof_report.py` crashed on a sample line with a frame lacking `:` (fixed: such frames are skipped).
- A whole-binary icount run with `--test-threads=12` moves by a few tenths of a percent between runs (memo timing): compare modules in one process, single tests with `--exact`.
- Review: `git checkout <file>` to drop a temporary probe also dropped an uncommitted test in the same file; commit wanted changes before probing.
