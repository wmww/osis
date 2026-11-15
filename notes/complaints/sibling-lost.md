# sibling-lost
- The brief named a repro (World::siblings(), issues/sync-unbuilt.md facade section, branch harness-pair) that is on no fetched branch: harness-pair is unrelated, capstan-sync-rebuild has neither. Had to rebuild the case from the sim's own-nodes test.
- The bug sits in the rebuild's engine facade (core/engine/src/sync/held.rs, on capstan-sync-rebuild only), so a worktree off origin/main cannot fix it.
