# store-audit
- No forensic test runs at the node-sync layer, so a real purge leak there was invisible to every shred test (issue filed); found only by reading.
- Review: gate took ~15 min on a box at load 87 (normally ~1.5); nothing wrong, just slow.
