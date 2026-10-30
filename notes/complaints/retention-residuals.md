# retention-residuals
> Summary: workflow notes from the retention-residuals task.

- Checking a fix by reverting one file (`git diff > patch; git checkout; test; git apply`) rebuilds the test binary twice per check (~2 min each under load); a probe that pushes the second rebuild past the 120 s tool timeout backgrounds the whole compound command, file swap included, so nothing may touch the tree until it ends.
