# s3-engine review
- `Hlc::peek` is not the wall clock: it jumps to every received `ts`, so a wait "until R's `ts`" written against it ends the moment R arrives. Rules that say "as of its wall clock" need `hlc.wall()`; a wait on wall time needs a wake (`Engine::next_timer`/`tick`), never a per-transaction re-check.
- Measuring a cost by `osis_perm::commits_walked` deltas in an engine lib test was quick and decisive (k vs 10k): a fair default for "who can force many walks" questions.
