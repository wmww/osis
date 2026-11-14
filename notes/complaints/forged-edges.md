# forged-edges
> Summary: Workflow snags met on the forged-edges branch.

- An issue's shrunk history fails only under the cfg its replay line prints (`random: 6, subsets: 4, ..ORDERS`, model on); under `NAMED` (model off) it passes, which reads as "does not reproduce". Issues should paste the exact `check(...)` line.
- held-model "applied" for a role commit means "held" (not thrown as unjudgeable), not "its edge writes apply": the 5019 report looked like a permission bypass until the node's roster showed the forged edges never applied. The diff message could say "held".
- Reviewer: gate 779 s wall, 6396 CPU-s at load 24 on ostrich, every stage over its share (the known ostrich clock pattern); nothing else in the way.
