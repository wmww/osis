# epoch-order-knowledge
- Waited 100-350 s for the heavy lock before each TLC run (seconds of work each); small TLC models could skip the lock.
- `tools/heavy bash -c` with nested quoting for a loop over cfgs is fiddly; run.sh only runs listed instances, so new cfgs need a hand loop until listed.
- A first engine test of the shape passed with and without the fix: a node of the account follows one side, so the other fork's epoch was already stale there. Check a new security test fails without the fix (reverting by `git checkout HEAD -- <files>` with copies saved, no stash).
- Review: three listed TLC instances (32 s of work) waited 7 min for the heavy lock behind a gate.
