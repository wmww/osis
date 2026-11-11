# engine-seeds-copy
- `grep -rl ... .` prints paths without `./`, so a `grep -v '^./rotation/'` filter let another worker's files through a mass sed; check `git status` after any bulk edit.
- `tools/icount BIN --exact NAME` measures one test per process, where a `cached` world is always built, never copied from another test's build: compare whole modules run in one process to see cross-test savings.
- Content rngs at 0 changed cost a lot in `apply::tests_paged` (`Rng::new(0)` drew a 3761-entry map): instruction counts compare histories, not only setups. Paged-test cost follows entry count, so fat entries are cheap, but padding of one repeated byte gives the content-defined chunker no cut (pages close only at `CHUNK_MAX`): vary the filler.
