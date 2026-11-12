# churn-022
- A debug env var named `OSIS_*` in temporary eprintln probes fails the run at start (testenv rejects unknown `OSIS_*` names): use a name without the prefix for throwaway probes.
- `OSIS_SYNC_TRACE` shows which blobs loop but not which rule judged them; per-node eprintln in `deletable` and `encrypt_again` (commit, why, per-part carrier and `covered`) found the cause in two runs.
