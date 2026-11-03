# Promotion's chain gate has no test
> Summary: `promote` refusing a deposit whose author's chain is not at the host is caught by nothing: tier 1 and 200 `link_race` seeds pass with it off. The other seed-pinned bugs have handmade tests (`osis-node` `pinned::`).
> Tags: tests, node-sync

`complete_chains` places the chain first, so the gate only shows when a writer applied a commit yet cannot place its chain, or its copy is refused while the promotion is taken (spec/sync.md §5; was link_race 41, 107, 120, 144, 197, 50). `Net::lose_uploads` loses both alike, so a test needs per-blob upload loss and a deposit with its chain missing at the host. `complete_chains` itself is pinned by `wrap_poison::useless_chain_entry_gets_a_copy_spec_sync_5`.

`host_loses_data` 41 never had a root cause: its issue closed with a bundled fix, so `sync_review::wiped_host_gets_bodies_back_from_restarted_node_spec_sync_6` was not sabotage-checked.
