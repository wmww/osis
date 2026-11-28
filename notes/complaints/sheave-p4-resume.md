# sheave-p4-resume
> Summary: lands refused by main moving while policy ran; shrinks of full-size seeds hit the 600 CPU-s seed timeout.

- `tools/land` was refused four times in one session because another commit landed while `tools/policy.py --baseline` ran (about 4 minutes at load 100), each needing a fetch, rebase and retry; one fix took three tries. A land that, for a rebase touching no file of the branch, re-runs only the cheap checks (or runs policy against the rebased tree after the fetch it pushes from) would have saved roughly 15 minutes.
- `OSIS_SYNC_SHRINK=1` on full-size differential seeds (15, 35, 86) hit the default 600 CPU-s seed timeout and reported "hung" after 15 minutes in a hold, with nothing shrunk; rerun with `OSIS_SEED_TIMEOUT_SECS=5400`. The issue's replay line should say a shrink needs a longer seed timeout (or the shrinker should lift it).
