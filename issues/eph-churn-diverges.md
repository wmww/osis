# random_churn_converges_large: nodes read different values
> Summary: `OSIS_EPH_START=934924146790 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large` fails on main d45be663a: node 1 reads a map value the others do not (convergence, not the rebuild check of issues/eph-churn-delete-upload-loop.md). Cause not traced.
> Priority: normal
> Tags: tests, node, sync
