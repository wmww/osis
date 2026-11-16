# A paired node cannot pair another
> Summary: `Engine::pair` at a node that joined its account by pairing sends commits after which the new node is not on D's roster: `paired` refuses `Permission` on D. Repro: osis-sync `flows::repro_a_paired_node_pairs_another_spec_sync_inbox_1`.
> Priority: normal
> Tags: engine, accounts

- Found by the reference-graph differential (its `Pair` step), which now pairs only from an account's first node until this is fixed (`history::history`).
- Same with no clock skew. The first node of the account pairs any number of nodes. Likely `pair`'s list (`certificates(&d)`, D's `sync.0` and `account.0` commits) misses what the second node's own rotation adding the third depends on as the second node holds it, so the chain at the new node does not reach the rotation that names it.
