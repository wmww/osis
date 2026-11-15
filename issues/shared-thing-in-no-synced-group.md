# A thing shared but in no synced group never leaves its node
> Summary: A node syncs only what its synced group's closure holds (spec/sync-set.md §2 Sync set), so a thing its account grants or links but lists in no synced group is not served: the grantee or redeemer accepts and waits forever. spec/requirements.md (Offline and network) keeps only a thing "in no synced group, shared with no one" local, so sharing should be enough.
> Priority: normal
> Tags: sync, tess-call

What users see: `create` (listed nowhere), then `grant(t, other)` or `make_link(t)`; the other account accepts or redeems, and `wait_synced(Thing(t))` never ends. Listing `t` in `home()` first makes it work (the osis tests and `osis_chat::create` do so).

Options: a grant or link by the account also lists the thing in home (the accept rule, spec/sync-set.md §4, from the sharer's side); or the sync set also holds each thing the account shares, whatever lists it. Either makes "shared" mean "synced" without filing what is shared with no one.
