# eph-churn
> Summary: Small workflow notes from the superseded-expiring-writes branch.

- The restored `many_authors_under_server_rates_spec_sync_9` takes 4.5-6.5 s in tier 1 (dev, load 11): 3.6 s of it is the 30 rounds of 10 nodes syncing, not the new checks (same with the rule off). Over the "few seconds" line; kept because the brief asked for 10 authors.
- `cargo test -p X --test it a:: b::` with two filters before `--` errors out (cargo takes one); piped through grep it looked like a silent pass. Put several filters after `--`.
- Review: `Net::advance` steps the nodes (takes unsent writes); to keep writes unsent between two moves use `net.clock.advance`. A first unsent-strip test passed with the fix off for that reason.
- Review 2: a 300-seed `run_seeds_noted` run hung for 15+ min on one seed with no output (it prints only failures at the end); running seeds one per process under `timeout` via xargs found the slow seed and gave per-seed logs. A hanging seed (44, with `Set` in the mix) never recurred without `Set`.
