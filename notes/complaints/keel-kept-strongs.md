# keel-kept-strongs
- sync `flows::a_node_pairs_another_after_removing_its_pairer_spec_sync_inbox_1` breaks on any change to commit bytes (a new setting field here); cost three bisect rebuilds to see it was not the new code (issues/pairing-misses-current-epoch.md).
- `git stash list` is denied by the permission rules even read-only; harmless, but surprising mid-command.
