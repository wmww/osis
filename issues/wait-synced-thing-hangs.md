# `wait_synced(Thing(t))` never ends for a redeemed thing that already synced
> Summary: after `redeem` + `accept_invite(t, home)` over real QUIC, `b.wait_synced(SyncScope::Thing(t))` ran to its 120 s timeout while `t`'s value had arrived in under a second and `status` showed t's sync ID `Synced`; only b's home was `NotConnected` (no other node of b's account).
> Priority: normal
> Tags: sync, osis

- Seen writing `runtime::two_accounts_sync_over_loopback_quic_spec_sync_transport_2` (it waits on `on_change` instead). Same likely on the ManualNet: swap its reads for `wait_synced` to reproduce in a fast test.
- Either the wait counts b's home as a sync ID carrying t (t is filed under home: spec/sync-status.md §3 "a wait on a thing covers every sync ID carrying it" would then never end on a one-node account), or b's own accept commit under home is waited for as "held elsewhere". Decide which sync IDs carry a filed thing for the wait, and say it in the spec.
- Hits `osis sync G` / CLI waits for any member filing a chat under home (notes/dogfood.md).
