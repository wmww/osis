# create-home
> Summary: workflow notes from the create-home branch.

- Started from key-closure before it merged into sync-rebuild; the later rebase conflicted on the one spec/sync-set.md §2 line both edited. Basing on an unmerged module branch saves waiting but buys a conflict.
- A test that passed before the rebase onto sync-rebuild (undo of creation, redo through home's `group.0`) failed after it with `NotKept`: home's unkept early history blocks a restoring redo. Worth knowing before filing things under home in undo tests.
