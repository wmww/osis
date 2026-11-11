# order-seeds
- `OSIS_ORDER_SHRINK=1` on a plain seed ran over 30 min per seed with no output until the end, and may settle on a different failure than the one replayed (458968566693 shrank to a text-order difference). A throwaway greedy step-dropper over `generate(seed, 60)` matching the failure text, run on a copied test binary, got 10-20 step histories in minutes.
- A shrink script that runs the test binary by path picks up every rebuild mid-run (same file name): copy the binary first.
- The order oracle's expiry excuse had been deleted from code while notes/testing.md still described it; three seed issues (and two more since) were filed as separate engine bugs before anyone checked the excuse.
