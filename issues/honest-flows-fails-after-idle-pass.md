# honest_flows_wait_for_no_resync fails on some seeds since idle passes
> Summary: since 6f50eac1 or d81eb8c6 (idle labels pass only when due, and its review) `honest_flows_wait_for_no_resync` fails on seeds 4 and 731200: uploads and deletes the full passes make never appear under work sets.
> Tags: tests, node-sync

Repro: `OSIS_SIM_FROM=4 OSIS_SIM_SEEDS=1 cargo test -p osis-sim --test it -- --ignored honest_flows_wait_for_no_resync`. The default seeds 0..2 pass, as do 2, 3 and 731201.

Seeds 4 and 731200 pass at c2efec0a, the commit before those two, and both fail at a3d529aa just after them (the same failure with simplify-sync on top).

The failing assert lists (host, label, kind, full passes' time, None): 'U' and 'D' entries at times like 5734000, 5917000, 6161000, 6222000. A key holds the blob ID, so a blob with other bytes (a heartbeat written at another moment) also shows as None. Not looked into: heartbeats written later than under full passes would make the oracle too strict here, while anything else is a trigger idle passes miss.
