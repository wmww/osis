# decode-step5
- Memory probes in one process are hard to read: glibc never gives freed memory back, so RSS only grows and a step's "peak" hides behind an earlier step's freed memory. `malloc_trim` would fix it, but `unsafe_code` is forbidden on the command line (`-F`), so not even a temporary probe can call it. Per-step marks of VmHWM (high-water growth between marks) were the workable substitute.
- Each probe of the writer needed a release rebuild of osis-node's `it` (3-5 min at load 25-35); five probes cost about 20 min of builds.
- A second commit rewriting every value of a paged 10^5-key map took about 450 s (issues/big-map-rewrite-cost.md), so the undo footprint could only be measured at 3x10^4.
- Review: `stream_memory_big_map`'s encode child dropped the 10^5-key input value before measuring, so the encoder reused its freed memory and read 0.4 MB (13 MB with the value kept). A one-process RSS probe must keep every big input alive across the measured step.
- Review: the fuzz target `delta` has no pages (`MemoryPages` empty), so it never reaches the `Pager`-in-check path this branch changed; the paged canonical-form coverage is `tests_stream` only.
