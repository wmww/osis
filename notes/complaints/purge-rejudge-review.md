# purge-rejudge-review
> Summary: Workflow notes from the purge re-judge review.

- `pkill -f <test name>` from a Bash call matches the shell running that very command and kills it (exit 144): stop a background run with TaskStop.
- A timing bench at N=10^5 with R=10^4 requests spends most of its time delivering (a named request's `on_apply` walks the aspect, about 15-40 ms each at 2*10^4); small sizes first.
- `order::` shrink of a 60-step seed: 8 minutes, one commit shorter. For a failure that is not an arrival-order one (dating), printing the aspect's commits at the failure answered it in one build.
