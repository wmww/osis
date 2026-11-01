# cli-own-admission
> Summary: Mishaps met while fixing `--admit own` on a dedicated host device.

- A bash fifo-based pairing repro deadlocked (both ends opening fifos in the wrong order); python subprocess was the quick way to drive `pair offer`/`join`.
- `pkill -f "$SCRATCH"` killed my own tool shell (its command line held the path) and the files I was writing in the same call.
- The tier-2 localhost test dropped `serve`'s stdout reader after the first line; `serve` dies on its next diagnostic (Broken pipe). Cost a round of misdiagnosis.
- `-v` (`verbose`) is parsed but not wired to anything: no way to see a CLI node's diagnostics without `diag --follow`, which needs the store lock.
- Review: tracing a node diagnostic in an osis runtime test took temporary `eprintln!`s (no diag stream in tests); `Internals::sync_engine` was the quick way to inspect either side.
