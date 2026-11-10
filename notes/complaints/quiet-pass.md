# quiet-pass
> Summary: workflow mishaps met on the quiet-pass branch.

- `wt claim quiet-pass` made the branch at main; basing it on another local branch (`net-deposits`) took a `git reset --hard` inside the worktree. A base option for `wt claim` would help.
- A test of "a role commit from elsewhere" first passed without the fix: the receiver places what it gets under the label (deposits of the commit, of a new holder's creation records), and the host's push back of that copy is a pass end. Use a role change on an existing holder and `lose_deposits` to see the bare case.
