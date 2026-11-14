# order-plain-m8
> Summary: workflow snags met fixing order seed 86543989744.

- `OSIS_ORDER_SHRINK=1` (one pass, 5 min) stopped at 27 of 60 steps: each removal redraws the seed's shuffles and subsets, so a step that matters to one order looks needed. A repeat-until-fixpoint loop over `check` reached 9 steps; the scripted 5-step reproducer came from reading those packs by hand.
- The order dump has no line for a pack's purge items; a scratch print of each header's `purge` list was what showed which request named which commit.
