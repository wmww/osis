# one-peer-3h1
> Summary: Footguns met building 3h1's first pieces.

- Three test harnesses (osis-node `Net`, sim `World`, sim `NetSim`) each build hosts their own way; making hosts nodes meant three separate plumbings of node sync above a hub. One shared helper for "a node's hub with node sync above it" would have made it one change.
- `hub_store_on` admits nothing by default, `HostStore::open` admits everything: a test host built on the former silently refused every label (all deletion tests failed with no diagnostic pointing at admission).
- Piping `cargo test` through `grep | head` in a background task cut the output mid-list and reported exit 0; write to a log file and grep it after.
