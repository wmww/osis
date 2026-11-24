# spar-engine-costs
> Summary: two cost issues stated their cause from a misleading measure; checking the baseline first would have saved the hunt.

- issues/covered-drop-dependent.md blamed dependent things; the independent case grew the same (its test passed by 1.4 KB): both were the store's key tree gaining a level at 256 slots, counted by backend bytes. An issue quoting a scale failure should quote the passing twin's numbers too.
- issues/deep-independence-cost.md and the brief quoted wall seconds (7 s, 15 s) on a box at load 30: the same test read 1 s to 15 s between runs. `tools/icount` and `CPUPROF_INSTR` (instruction-based, load-proof) gave stable numbers; briefs should quote those.
