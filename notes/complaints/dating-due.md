# dating-due
> Summary: Workflow notes from the dating-due cost fix.

- `tools/claim` started the branch at origin/main while the main checkout's `main` was a few commits ahead (unpushed local commits there); a fresh session reading the gitStatus snapshot sees a different base than its worktree.
- A scale test needs some in-transaction date reader to exist: woken pending commits on a kept aspect read no date unless a commit listener is set (`listen_commits`), so the first draft counted 0 reads.
