# review-early-grant
> Summary: workflow notes from reviewing the sync ID fork ticket fix.

- Whether a re-seal's commit is readable from the sync ID by a holder holding another current box needs spec/crypto.md §5 Who wraps under what plus spec/sync-inbox.md §5 read together; the Key changes bullet stated a condition the wrap rule contradicts. One line in Key changes pointing at the wrap rule would have saved the cross-read.
- `tools/land 2>&1 | tail -5 && git push --delete ...`: the pipe's exit is tail's, so the branch delete ran though land refused (main had moved). Run land unpiped.
