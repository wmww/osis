# main-order-bugs
- The order shrinker dropped steps of a `settled` history's tail (syncs, compactions), so the shrunk 551505 history no longer settled anything and pointed at a forged commit that had nothing to do with it (17 min spent). The shrinker now keeps the tail whole.
- `wt claim` exited 1 while printing a working worktree path.
- Greedily shrinking an arrival order (drop one pack while it still fails, one test binary run per try, about 1 s each) found both minimal orders in about 2 min; worth a harness knob next to `OSIS_ORDER_SHRINK`.
