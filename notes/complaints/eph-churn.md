# eph-churn
> Summary: Small workflow notes from the superseded-expiring-writes branch.

- The restored `many_authors_under_server_rates_spec_sync_9` takes 4.5-6.5 s in tier 1 (dev, load 11): 3.6 s of it is the 30 rounds of 10 nodes syncing, not the new checks (same with the rule off). Over the "few seconds" line; kept because the brief asked for 10 authors.
- `cargo test -p X --test it a:: b::` with two filters before `--` errors out (cargo takes one); piped through grep it looked like a silent pass. Put several filters after `--`.
