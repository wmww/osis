# deposit-leftovers
- The Net sim pushes small blobs inline, so a "head before its commit" race never shows with default nodes; it needs `inline_limit: 0` on the lagging node. Worth knowing when an issue says a pass runs before the download.
- LocalPeer engine tests: `forget_lost` reloads and re-examines, which re-reads pending boxes as candidates; a test that only checks `held()` (checked secrets) misses candidates coming back.
- Reviewer: a sim sweep started in the background before review edits rebuilt the tree mid-run with half-made edits; start oracles only after the code is final, or rerun.
