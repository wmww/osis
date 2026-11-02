# required-retention-review4
- `net.round()` with an empty queue does nothing and does not look at engines, so `while !cond { net.round() }` spins for good (cost 3 min before the 180 s move to background). `net.run()` is the step.
- `Net`'s `node(seed, &[h1])` does not confine a node to `h1`: it connects to every host of the label's addresses. Isolating one takes `drop_link`, and links come back on a later tick.
- `pkill -f <pattern>` in a Bash call matches the call's own shell and kills it (exit 144): the rest of the command never ran.
