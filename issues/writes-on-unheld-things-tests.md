# Engine tests whose corner needs a write on an unheld thing
> Summary: A node writes only what it holds (spec/sync-set.md §2 Writing). These tests reach their corner only by writing a thing outside the writer's node closure and are ignored until rebuilt: `retention::compact::tests::writer_compacts_once_its_delete_keys_arrive_spec_sync_7` (rebuilt so the writer holds `t` by write on its admin, an independent thing, it then compacts with `holds_delete_keys` false: a gate reading derived keys, or the test's?), `validity::record_then_edge_chain_applies_spec_perm_1` (the writer writes C by a bare-edge chain and holds no key of C; a read grant by the flow to hold C makes its write apply at once where the test wants it pending on A's record).
> Priority: normal
> Tags: engine, tests
