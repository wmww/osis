# D's holds.0 strongs only the creating node, not each node of P
> Summary: spec/sync-set.md §1 says the account root's `holds.0` holds a strong to the node thing of each node of P; only `create_account_in` writes one (its own node), `pair` and `remove_device` write none. Retention keeps a device by its account's chain instead (`retention::needed` `Need::Holder`, `AccountView::named_device`), so nothing goes missing; either the spec sentence or the code changes.
> Priority: low
> Tags: engine, retention

If pairing wrote the strong (and a removal took it out), a device would be needed as any strong's target and the chain-named device need in `needs` could go: one mechanism. Check first what else reads D's strongs to node things (the walk does not enter key actors; `NotCarried` excludes them).
