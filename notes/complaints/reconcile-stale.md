# reconcile-stale
- Node test `Net::wipe_host` keeps the nodes' links to the old hub: a node that stays online never reconnects to the wiped host (silently reads stale data). Take nodes offline around the wipe, as `replaced_label_reregistered_where_lost` does.
- `reconciled` lives in sync/inbound.rs, not sync/mod.rs as briefed.
- Review: the brief said `absent_at` records the delete in `deleted`; it does so via `remove_entry` (state.rs), only for commit entries, only once present nowhere.
- Gate after rebase failed: disk full (/ 100%, rustc 'No space left on device'); 8 worktree targets hold about 54 GB of it.
