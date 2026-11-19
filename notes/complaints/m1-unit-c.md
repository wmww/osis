# m1-unit-c
> Summary: Workflow notes from the unit model's over-time brief.

- The full-family run (three ignored twins, about a minute of work) waited 20+ minutes for the heavy lock behind another all-core run; a short by-hand run has no cheaper queue.
- The first over-time `Net` recomputed every view from scratch at each delivery, visit and pass: 50 s for the unit suite. Memoizing both sides' views by commit count (commits and holdings only grow) brought it to about 5 s.
