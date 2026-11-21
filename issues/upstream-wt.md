# Fixes wanted upstream in `wt`
> Summary: Two fixes wanted in the `wt` script (reasonable-rust-builds plugin, wmww/agent-skills), for Tess to forward; osis's workarounds are in notes/build.md, Worktrees.
> Priority: low
> Tags: workflow, tess-call

- **Release: detach first, then prune.** `release` prunes the target (its marking build takes 1-4 min on a first release) while the branch is still checked out, and detaches HEAD only after. Meanwhile `wt claim <same branch>` in another worktree fails with git's "already used by worktree"; the coordinator hit it twice landing branches whose worker's backgrounded release was still pruning. Detaching first frees the branch at once, and the claim marker (removed last) still keeps the worktree from being handed out mid-prune. Until then, a claim failing this way could say "<path> is being released (still holds <branch>): retry when `wt list` shows it free" instead of git's message.
- **Claim of an existing local branch ignores the base silently.** `wt claim <branch> <base>` checks out the local `<branch>` when it exists and drops `<base>` without a word, so a reviewer got a stale local copy (an earlier pre-rebase state of the worker's work, not an ancestor of its push) twice. Wanted: when a base is given and the local branch is neither it nor contains it, print a warning naming both commits (or refuse unless `--existing`).
