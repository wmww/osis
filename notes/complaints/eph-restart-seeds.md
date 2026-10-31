# eph-restart-seeds
- The eph seed replays print no node-sync or engine trace: finding where a commit went took temporary eprintlns in `eph_added`, `reconciled`, `fetch_on`, `lost`. A per-node lane trace (like OSIS_SIM_TRACE) would have saved two rebuilds.
- `random_churn_converges_spec_sync_9` already takes about 7 s in tier 1 (4 seeds); pinning a seed there costs over 1 s, so the fixes are pinned by focused tests instead.
- Review: tracing the churn seeds took five instrument/build/run rounds (temporary eprintlns in `release_held`, the pending promotion, `reconciled`, `sync_label`). Same need as above: an env-gated lane/held-set trace keyed by commit or blob prefix.
