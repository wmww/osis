# Ephemeral inflight oracle: a restarted writer misses its earlier session's commits
> Summary: `ephemeral::random_window_inflight_large` seed 100013 fails on main too (found in review of eph-unify-2): after two restarts node 2 reads `k3=v4` and no `k0`, while nodes 1 and 3 hold node 2's earlier-session commits (`k3=v18`) and read alike; node 2 never gets them back.
> Tags: ephemeral, node-sync, tests

Replay: `OSIS_EPH_START=100013 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_window_inflight_large --nocapture` (cap 4000; no refusal reported). The other 199 seeds from 100000, and the `converges`/`one_capped_server` variants at 200 seeds, pass.

Possibly the step-1 divergence noted in issues/eph-unify.md (an author gets its thing back without its own earlier writes); step 3 (held bodies through Core) is expected to remove it: check this seed there.
