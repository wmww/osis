# reconcile-stale
- Node test `Net::wipe_host` keeps the nodes' links to the old hub: a node that stays online never reconnects to the wiped host (silently reads stale data). Take nodes offline around the wipe, as `replaced_label_reregistered_where_lost` does.
- `reconciled` lives in sync/inbound.rs, not sync/mod.rs as briefed.
