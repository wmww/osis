# held-set
> Summary: mishaps met fixing the settled held-set failure.

- The shrink (`OSIS_ORDER_SHRINK=1`, one seed of 60 steps) took 9 minutes under the heavy lock; the shrunk 6-step history then replayed in a scripted test in 20 s, so the shrink is worth it, but its printed history must be hand-edited (`Aim(X)` prints without its `Box::new`) before it compiles.
- `OSIS_ORDER_DUMP` names a part `missing` without saying why (dropped while invalid shows no drop reason): finding the invalid drop took moving each commit late in turn.
