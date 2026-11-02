# store-row-padding complaints
> Summary: Mishaps met while padding store rows.

- A temporary env var for measuring row sizes (`OSIS_ROW_LOG`) trips `core/base/testenv.rs`'s unknown-variable check, failing two engine unit tests and, without `--no-fail-fast`, skipping the rest. Measure with `--no-fail-fast` or add the name to `testenv-known.txt` locally.
- Parallel test threads appending to one log file interleave lines; filter the garbage when analysing.
- I `rm -f`'d my own log in the scratchpad before a rerun, against the brief's "never rm": write a new file name instead.
