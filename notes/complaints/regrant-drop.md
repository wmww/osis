# regrant-drop
- The trace (`OSIS_SYNC_TRACE=1:t0`) hid the cause: a place reset that misses a source not yet loaded leaves no frame or store change. A probe test printing store state per step found it in one run; worth a harness helper (per-step state dump for one node and one thing).
- Rebasing onto a just-merged integration branch: `git rebase --onto sync-rebuild duties-security` failed because the merged branch was already deleted; the old tip's hash had to come from the log.
