# boxes-verify
> Summary: workflow snags met on the boxes-verify branch.

- The base branch (holder-roster) was deleted once merged; `git rebase sync-rebuild` then replayed its whole history and conflicted. `git rebase --onto sync-rebuild <old base tip>` worked: briefs that start from a module branch should name its tip commit, not only the branch.
- The brief's two options both missed that a forger can sign as a key actor of its own: verifying the signature proves who the author is, not that it may grant. Worth a hostile-party pass on a brief before it goes out.
