# churn-884
- `OSIS_*` debug env vars panic as unknown (testenv-known.txt): ad-hoc trace switches need a non-OSIS name.
- `OSIS_SYNC_TRACE` prints frames but not commit IDs or judgments; finding the two disagreeing rules took four instrumented 3-5 min rebuilds (engine changes rebuild osis-node's test binary).
