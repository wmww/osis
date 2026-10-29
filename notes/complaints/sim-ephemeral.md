# sim-ephemeral
- The sim's verbose trace printed every proto message truncated to 110 chars, so an Upload loop showed only blob bytes; `frames` now prints uploads as blob ID, class and size.
- Sizing a capped scenario took several rounds: `held_ephemeral` sizes are heap bytes (4-12 KB) while blobs are about 1.5 KB plus 864 B of server overhead; a 6 KB cap holds less than the compacted state of two things and three writers, so the label legitimately stops syncing. Server `ephemeral_bytes` per label at quiescence is the number to size from (now a trace line).
- A tier-1 node test hand-built to reproduce "refused entry never retried" passed on main (the refusal never happened in that layout); the sim seed became the regression test instead.
