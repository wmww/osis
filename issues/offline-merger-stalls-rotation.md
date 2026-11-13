# An offline merger can stall a rotation that needs a forked holder actor merged
> Summary: Forks of a holder actor M are merged by one merger picked from M's roster (spec/crypto.md §4). If M has forked, actor A must rotate (a departure) and the node rotating A may not rotate M, A's rotation waits for the merger: writes to A wait with it and A's holders read nothing new until the merger returns or is removed from M. For an account the merger is its first node by device order, often its oldest device. Clashes with "every operation completes with nobody else online".
> Priority: normal
> Tags: keys, rotation, tess-call

## Options
1. Accept it as a stated limit (spec/requirements.md would need to say so).
2. For an account, pick its newest device as merger instead of its first: as deterministic, more likely online.
3. Rethink the Seal wait. Boxing M at each fork is ruled out: it leaks to a member removed from M.

Before rotation-storm-2 the merger was whoever made the fork (usually online), but merges forked each other (member_churn 204 commits vs 109 now).
