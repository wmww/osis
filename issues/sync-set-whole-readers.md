# Engine readers of the whole sync set
> Summary: `Engine::sync_set()` is one memo over `sync_things()` and every thing's `thing_sync`, rebuilt whole (O(N's closure)) after any sync set change; `passes_wanted`, `read_things` and `reads_now` read it on per-change paths, so adding n things one at a time costs O(n²) there.
> Priority: normal
> Tags: engine, sync

`osis_sync::set::SetFollow` follows the sync set per thing (`Engine::things_entered`, `in_sync_things`), but these engine readers still take the whole fold:
- `held.rs` `reads_now(s)` (each `note_complete_pass`): one sync ID's holding. `sync_holder(s)` answers it per S.
- `passes_wanted_fresh` (status, each settle): issues/sync-passes-wanted-whole.md.
- `certified.rs` `read_things` (`Certified::read`): issues/certified-leftovers.md.
- `caught_up_fresh` (only while a group moves home: a rare path, may stay whole).

Fix shape: per-S or per-thing memos fed the same way `SetFollow` is (the `ThingsFeed` candidates, then a per-key settle), leaving `sync_set()` and `sync_things()` for listing and debug checks.
