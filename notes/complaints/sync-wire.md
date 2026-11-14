# sync-wire
- "Count allocations" for decoder limits: the workspace `forbid(unsafe_code)` lint reaches test targets, so a counting `#[global_allocator]` cannot be written; the limit tests check sizes and refusal before building instead.
- spec/wire.md §2 gave `MAX_RESUME_TAGS` as ⌊(MAX_MESSAGE − 64) / 33⌋, but a 32-byte tag encodes in 34 bytes: the cap's message did not fit a frame. Only a cap-sized test showed it.
- The vectors generator and examples are the only callers of most new osis-proto items until osis-sync lands, so each needed a `tools/dead_pub_allow.txt` line.
