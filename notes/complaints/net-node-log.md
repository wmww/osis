# net-node-log
> Summary: Mishaps building the node log.

- `Faults::at(n, ..)` resets the write counter and counts from now: `at(writes() + k)` silently plans past the end. Its doc says so; easy to misread.
- A `(cmd | tail); echo ${PIPESTATUS[0]}` run in the background reported the wrapper's exit, as notes/build.md warns: read the `test result` lines.
- A mutation that only changes a non-committing read path passes every test: tests of "writes nothing" must commit the read transaction.
- Review: a read-path mutation in `log_cursor` passed every test until the read test committed that read too: same trap as above.
