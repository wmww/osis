# key-closure
> Summary: workflow notes from the key-closure branch.

- The issue to delete lived only on an unmerged branch (small-fixes): the branch cherry-picks its repro commit so the delete applies whichever merges first; small-fixes then needs a rebase (skips the commit), not a merge, or its tip dropped.
- `cargo test -p X --test it a:: b::` fails (two filters need `--`): `cargo test -p X --test it -- a:: b::`.
- Review: the branch broke 5 `-p osis` tests (scratch groups made under home now sync by key home); an engine change that moves what syncs needs `-p osis` in the worker's run, not only engine and sync.
