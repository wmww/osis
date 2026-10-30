# deposit-leftovers
- The Net sim pushes small blobs inline, so a "head before its commit" race never shows with default nodes; it needs `inline_limit: 0` on the lagging node. Worth knowing when an issue says a pass runs before the download.
- LocalPeer engine tests: `forget_lost` reloads and re-examines, which re-reads pending boxes as candidates; a test that only checks `held()` (checked secrets) misses candidates coming back.
