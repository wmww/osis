# pulled-refusal
> Summary: workflow mishaps met on the pulled-refusal branch.

- The test net cannot make a peer honestly refuse an entry the source judges stamped for the peer's head: the source learns a peer's head only from that peer, in order, so a keys-not-held refusal of such an entry exists only in a race (the sim's `member_churn` shows code 1 and 9 refusals often, all resolved by a restamp or a head move). The default test injects the refusal (`Net::host_inject`); a first honest attempt (an admin demoting while away from the host) produced no refusal at all, which took a probe to learn.
- `cargo test` hides `eprintln!` of passing tests: a probe needs `--nocapture`, else it looks like the code path never ran.
- A test whose purge "went" can pass for the wrong reason: another writer (b) deleted it. Check which node acted before trusting a pass, e.g. by making the other members readers.
