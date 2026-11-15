# fathom-held-plain
> Summary: held-model drop-judging footgun; the order property's scope skips hide coverage.

- held::compare feeds an out-of-scope aspect's bodies as empty; anything remembering them across judgments (the `Drops` seen map) must check scope at the time it records, or an empty body reads as a live one.
- Finding why a seed's coverage floor fails needs knowing which held sets were out of scope and why; `Coverage::skipped` counts reasons but names no commit. A probe printing `scope()`'s role-out reasons found it in one run.
- `OSIS_ORDER_SHRINK=1` is impractical on a 60-step plain seed (a full check per dropped step); a targeted probe (debug print in the failing check) was faster.
