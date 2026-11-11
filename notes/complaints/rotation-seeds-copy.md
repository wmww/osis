# rotation-seeds-copy
- `tools/icount` run in parallel on first use builds `icount.c` concurrently: about 50 of 128 runs printed no `INSTR` line (looked like failures). Run it once alone first.
- Per-test `tools/icount <bin> --exact <name>` cannot show a `cached` saving (one process per test, the cache built in each); only a run of the module's tests in one process does.
- `tests.rs` `Rng(0)` is a dead xorshift (stays 0): a seed of 0 there silently fixes every draw.
