# Churn seed 9130190: a node's upload and delete loop without end
> Summary: `random_churn_converges_large` seed 9130190 never settles, on main and on eph-lane: on eph-lane one node (the admin) alternates an Upload of a new blob with a Delete of its previous one by the label delete key. Cause not found; found on the eph-lane review. In real time it would be a steady storm between those messages.
> Tags: ephemeral, node-sync, tests

Replay: `OSIS_SEED_TIMEOUT_SECS=15 OSIS_EPH_START=9130190 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large`. 1 of 300 seeds from 9130000. `OSIS_SYNC_TRACE=1` shows the loop; the other nodes only receive the pushes. Not yet known: whether main's loop is the same one, and what the uploaded commit is (a fresh snapshot each round would point at the trigger or `take_memory_invalidated`).
