# rotation-depth
- `wt` was not on PATH (plugin bin dir had to be exported by hand).
- An engine-level random differential costs about 0.5 s per scenario (each grant/demote is a full commit with rotation), so tier-1 keeps 6 seeds per variant; 200 seeds took 2.5 min by hand.
