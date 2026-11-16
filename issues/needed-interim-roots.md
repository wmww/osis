# Interim roots of what a held thing needs
> Summary: `retention/needed.rs` also keeps a thing this node may read or holds content of (but in the transaction releasing it), because engine tests hand peers commits of things no strong holds at the receiver; remove the root once they hold what they receive.
> Priority: low
> Tags: engine, tests

The rule (spec/commits.md §5 Forgetting, What a held thing needs) keeps a thing outside the node closure only while a held thing needs it. The making rule refuses a local commit making a thing outside the closure, but nothing makes a receiver hold what it is handed: engine tests deliver packages directly (`LocalPeer::deliver`, `spread`, `sync_all`), so a peer holds others' things, readable or not, with no strong. Without the interim root about 60 engine lib tests lose such things when a need of them goes (the index check or their reads fail: `apply::tests_addenda`, `tests_paged`, `tests_order`, `engine::tests::failed_transaction_restores_indexes_*`, ...). `LocalPeer`'s plaintext delivery also hands bodies a real node could not open, so "holds content" there is not what a node holds.

Fix: test helpers hold what a peer is handed (a strong at the receiver, as `Engine::new_thing` does for the maker), then drop `rooted`'s interim clause and `Core::released_now`, and check the engine tests and the census tests again.
