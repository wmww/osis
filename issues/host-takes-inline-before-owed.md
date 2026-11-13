# A node that cannot read a label takes an inline entry before an earlier one it still fetches
> Summary: spec/permissions.md §3 places a removal before the content beside it. A node pulling an unread label takes an entry that comes with its bytes at once, so one announced after an entry whose bytes are still being fetched (a removal past the inline limit, then small content) is logged first there.
> Priority: normal
> Tags: sync, node-sync

- Where: `SyncEngine::unread_events` (core/node/src/sync/unread.rs) takes byte-carrying events at once; entries announced without bytes wait in `Unread::pending` and are taken in announcement order (`unread_take_held`, `unread_order`). Nothing orders an inline take behind a pending one.
- Tried in review: keeping a later entry's bytes in `pending` while an earlier one of the label waits. It broke `ephemeral::ephemeral_signals_not_held_back_spec_sync_9`, `fill::no_pass_before_order_0_spec_sync_6` (a loop) and `sync_more::departed_reader_connected_across_new_step_spec_sync_5`, even with the memory classes exempt; not traced.
- Test to add: `removal_placed_first_under_every_label_spec_perm_3` with the hosts' inline limit between the content's and the removal's size.
