# reach-index
- `tools/bin-at origin/main` to compare one default test's CPU-s against main rebuilt the whole engine test binary twice (about 6 min, the tree unusable meanwhile) for a two-number answer; a kept main-built binary per base commit (notes/build.md, Wished) would have made it seconds.
- `tools/mutate.py` refuses an OLD inside a `const` (the plant's `OnceLock` read is not const): planting a test's `const Config` did not build; plant the constructor in the library instead.
- A shell `${O/a/b}` substitution in a mutate.py command was auto-denied by the harness; write each NEW literally.
