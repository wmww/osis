# label-ownership
- `cargo test -p osis-node` passing is not enough for an engine change to label judgement: the first-own-secrets and K-keyset-before-box cases fail only in `-p osis --test it` (sharing::*). Run it before believing a label.0 change.
- Destruction/forget tests that check "sync state stays" by row counts flap by one row between passes; compare at a point with no run in between (`drop_lost_due` by hand after `pair`) or assert > 0.
- Review: the first gate refused (origin/main moved 4 commits during review); a second rebase and the gate's full rebuild.
