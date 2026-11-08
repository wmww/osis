# purge_author arrival order: a node shows a purged author's message
> Summary: `order::arrival_order_purge_author_large_spec_perm_6` seed 452234901986 fails, on main c3c622720 too: a node holding a partial set (order #8) shows `t:reg.0` = `"m7"` after the sync exchange where the node keeping every body shows `None`. Not root-caused or shrunk.
> Priority: normal
> Tags: engine, retention, tests

Replay: `OSIS_ORDER_SEED=452234901986 OSIS_ORDER_LEN=50 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_purge_author_large_spec_perm_6` (1.7 s; `OSIS_ORDER_SHRINK=1` shrinks). The history ends in purge-author requests on thing 0 (`PurgeAuthor { by: 0, t: 0, of: 2 }`, `PurgeAuthor { by: 2, t: 0, of: 2 }`) after node 2 is granted write there. Start with which reading the spec gives (spec/permissions.md §6), then shrink.
