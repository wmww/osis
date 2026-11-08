# half-valid
- `wt claim half-valid` made a branch `half-valid` at main, so the brief's `git checkout -b half-valid rotation-fix` failed; `git reset --hard rotation-fix` on the claimed branch instead.
- A TLC operator recursing to a fixpoint that does not exist dies with a StackOverflowError (run.sh reports `error`), not a violation: state uniqueness as "every fixpoint equals the result" instead of computing one.
- Depth0's `Beaten` read `ReachD` of the removed party itself, empty for an actor: `NoLeakLimit` passed or failed vacuously on actor removals (fixed: `ReachP`, its devices).
