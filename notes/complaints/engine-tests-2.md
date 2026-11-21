# engine-tests-2
> Summary: Footguns met while cutting engine default-test cost and fixing the follow-count variance.

- A count test counted something no test controls: `memo::writes` is process-wide, so follow counters moved with other tests' writes; copies.rs had silently filtered them out instead of the count being fixed. A filter in one test is a carve-out: look for the same excuse elsewhere before trusting a count.
- `seq_placement_differential_after_reset` never reached its own claim (no strip hit a long insert); nothing tallied it. A claim in a test's comment needs a tally, or it is unchecked.
- `rg -h` is help, not "no filename" (that is `--no-filename`).
