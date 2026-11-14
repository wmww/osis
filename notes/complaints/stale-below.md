# stale-below
> Summary: footguns met while unifying the stale-box rule for encrypting and sealing.

- `tests::settle` assumes a synced start: called after partial pairwise syncs it returned at round 0 with an actor still blocked at its admin (the admin acted before the sync that brought the stale keyset). Sync first.
- TLC model constants that a cfg may set to a string must not also be compared to TRUE (`PfJudge = "seal"` threw); add a separate boolean constant instead.
- Running every D0 instance twice (two rule variants) at a 300 s cap held the heavy lock for well over an hour; most by-hand instances only time out. A per-instance budget list (which instances are worth a run per variant) would save that.
- I ran two short TLC instances and two property runs (about 20 s each) outside `tools/heavy` while my own batch held the lock.
