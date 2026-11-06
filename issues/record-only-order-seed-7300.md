# Record-only arrival order: seed 7300 reads roles.0 by arrival order
> Summary: `order::arrival_order_record_only_large_spec_permissions_2` seed 7300 fails on main too: a node's `roles.0` read of one thing differs from the node keeping every body (a different holder, admin against write). Convergence bug, root cause unknown.
> Tags: permissions, node

Replay: `OSIS_ORDER_SEED=7300 OSIS_ORDER_LEN=40 cargo test -p osis-node --test it -- --include-ignored order::arrival_order_record_only_large_spec_permissions_2` (`OSIS_ORDER_SHRINK=1` shrinks it). Order #3 of 55 commits: the later node reads one holder at admin where the keep-every-body node reads another holder at write. The history mixes record-only things nested under each other, grants, removals (one `lower: true` of the first admin on thing 0), a demotion and compactions. Plain size, offset 7300: 1 of 6 seeds.
