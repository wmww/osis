# Churn oracle seed 79 reads a value past its expiry
> Summary: `ephemeral::random_churn_converges_large` seed 79 (in the default 0..200 range) fails since fed16434 put `Set` back in the oracle: node 1 reads v3 711 ms past its expiry at step 56.
> Tags: tests, node, ephemeral

Repro: `OSIS_EPH_START=79 OSIS_EPH_SEEDS=1 cargo test --workspace --test it ephemeral::random_churn_converges_large -- --ignored --exact` (4 s). Passes at fed16434^, fails at fed16434 and main 4210a930 alike (found by the tier1-trim review; that branch does not change it). Not looked into: whether the `Set` history exposes a read-past-expiry bug or the oracle's expectation for a `Set` into an expiring entry is wrong.
