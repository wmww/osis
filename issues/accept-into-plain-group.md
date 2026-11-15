# `accept_invite` refuses a plain group under a synced group
> Summary: spec/sync-set.md §4 lets an accept write the thing under a synced group or a group under one; `Osis::accept_invite` asks that `into` own a sync ID in the sync set, so a plain group listed under home (no secrets of its own) is refused `Invalid` ("not synced here").
> Priority: low
> Tags: osis, sync

- Fix: judge `into` by the synced closures (`Engine::synced_closures`, pub(crate) today) instead of the sync set's sync IDs.
- Seen in cli `invitations_accept_and_relay_commands` (a `--local` group; refusing that one is right either way).
