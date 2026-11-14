# memo-narrow
> Summary: Footguns met narrowing the memo stamps: no committed rerun counter, `testenv` refusing an unknown variable, libtest swallowing a counter's stderr.

- Counting memo reruns (and which read moved) needed a throwaway counter in `memo::Memo::keep` plus `#[track_caller]` on every container read again: each round of this issue rebuilds it. An env-gated counter kept in `memo` would save the rebuild.
- A new env var for a probe fails every binary at start (`testenv-known.txt`) until listed; a probe counter read through `eprintln!` inside tests is captured by libtest unless `--nocapture`.
- `osis` `sources::` instruction counts move a few percent between identical runs (thread timing): a 1% lever cannot be told from noise there; sim seeds are steadier.
