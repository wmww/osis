# purge-rights-review2
- A sim scenario asserting "body past keep at most is gone" cost three rounds: the sim's random workload writes go on during `quiet`, and absolute at-most is not built (known, issues/absolute-keep-at-most.md, found late: grep issues first).
- `check::convergence` compares reads only between nodes holding the same deltas, so "reads alike with different bodies" needs its own check in a scenario.
