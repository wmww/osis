# boxes-verify
> Summary: workflow snags met on the boxes-verify branch.

- The base branch (holder-roster) was deleted once merged; `git rebase sync-rebuild` then replayed its whole history and conflicted. `git rebase --onto sync-rebuild <old base tip>` worked: briefs that start from a module branch should name its tip commit, not only the branch.
- The brief's two options both missed that a forger can sign as a key actor of its own: verifying the signature proves who the author is, not that it may grant. Worth a hostile-party pass on a brief before it goes out.
- (review) Engine tests stood in for "the user accepted it" and "stamped" by passing `true` to `take_inbox_blob`, which nothing in production passes; the sync harness's `file` wrote by `Engine::commit`, which skips `mark_acted`, so no World test ran an accept as the product does. A whole flow (one stranger's grant, accept on one node, its sibling) found both gaps at once.
