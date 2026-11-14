# harness-pair
- The harness's per-test delivery cap panics with "storm: past 2000 deliveries; still flowing ..." also when a test simply ran long (cumulative deliveries over many runs, nothing looping): read `d<n>` in a trace before hunting a storm.
- A mutation of a sibling-only rule (status/live.rs own-node filter) survived because siblings prove both node and account: each disjunct alone suffices; mutate the whole filter to see the test bite.
