# fathom-held-plain
> Summary: held-model drop-judging footgun; the order property's scope skips hide coverage.

- held::compare feeds an out-of-scope aspect's bodies as empty; anything remembering them across judgments (the `Drops` seen map) must read the real body (`held::unread_body`), or an empty body reads as a live one. Skipping such parts instead hid a planted drop of a body in history (review).
- `held_set_decides` (default) is about 240 CPU-s, 20-40 s wall at load 10-36; its knobs barely cut it (12 steps and minimal orders: 140 CPU-s; the emphasis starts set most of a history's length). The lever is issues/tests-4x.md's prefix tree walk.
- Finding why a seed's coverage floor fails needs knowing which held sets were out of scope and why; `Coverage::skipped` counts reasons but names no commit. A probe printing `scope()`'s role-out reasons found it in one run.
- `OSIS_ORDER_SHRINK=1` is impractical on a 60-step plain seed (a full check per dropped step); a targeted probe (debug print in the failing check) was faster.
