# sextant-model-reconcile
- A "settled" check that compares state before and after a whole round misses a flip inside the round (one node logs, another deletes, net zero). Count changes per step instead; the model's `Sync::churn` does.
- `--report-time` needs nightly; there is no stable way to get per-test times from the harness.
- The branch's spec/sync-set.md §2 still describes leaves and "gone for everyone", which the revised plan dropped. A worker on the model meets the contradiction first and has no brief to fix it.
