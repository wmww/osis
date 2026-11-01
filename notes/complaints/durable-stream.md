# durable-stream
> Summary: worker complaints from the streaming canonical check (steps 1-2 of issues/durable-decode-bound.md).

- `history_with` random histories stay a few hundred bytes (a replace or remove wipes earlier writes), so nothing pages even at tiny page parameters; added `testutil::history_bulk` (a large last write per writer). Root `Slots` (writers on different types) keep their sequences out of streaming: per-type cases needed.
- A fuzz run leaves hundreds of untracked files in core/test/fuzz/corpus/delta: `git clean -fq core/test/fuzz/corpus/` before committing.
- Peak RSS of a decode step needs a child process per step (glibc keeps freed memory, so a second step in one process reads low); `stream_memory_big_map` re-runs its own test binary.
