# purge-imports
> Summary: Mishaps on the purge-imports task.

- Under load a test binary rebuild takes 3 min. A one-build mutation run helped: every probe behind one `PROBE` env check in a wip copy, then one loop over the same binary, and `git checkout` to remove them.
- The order oracle had no move or import step, so nothing checked imports for arrival order until this branch.
- Review at load 40: `timeout 280 cargo test --workspace` killed tier 1 before osis-node `it` with a green-looking list of results, so a new decode check reached the oracles and only the gate caught it. Tier 1 needs no bound: run it to its end.
- Rebase onto purge-rejudge: squashing first left one conflict pass instead of two. A helper `ls -t tasks/ | head -1` to find my task's ID picked another agent's task: use the ID the tool printed.
