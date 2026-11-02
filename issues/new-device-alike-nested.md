# new_device_alike_large fails on nested writes
> Summary: osis-node `order::new_device_alike_large_spec_permissions_5_1` fails 13 of its 256 default seeds (1, 19, 24, 52, 54, 95, 139, 149, 162, 177, 199, 217, 246) and 8 of 31700..31956, alike on main, before item 223 (53453167) and with frontier F2. Most shrunk histories have `Nested`/`NestedItem` writes compacted by another node (seed 54 has none: a map write, compaction, undo): the fresh node, lacking the covered parts, reads a different nested map value or text (`v7v4v1` against `v7v1`). Reviewer confirmed the same 13 seeds fail with main's binary (`tools/bin-at main`).
> Tags: tests, engine, permissions

Replay: `OSIS_ORDER_SEED=31953 cargo test -p osis-node --test it -- --ignored --exact order::new_device_alike_large_spec_permissions_5_1 --nocapture`. Shrunk: `h = vec![Aim(Nested { by: 1, other: 0, t: 3, k: 0, text: true, compact: true, also: false }), Aim(Demote { by: 0, t: 5, holder: 1, at: 3, to_read: false }), Aim(Nested { by: 0, other: 1, t: 0, k: 0, text: true, compact: false, also: true })]`; `t:docs.0` every body `{"k0": "v7v1"}`, after covered drops `{"k0": "v1v7v1"}`.

Not yet known whether the harness's model of what hosts keep (`check_new_device`: drops each part a held snapshot covers, whatever its retention or validity) is wrong or the engine is. Not in the per-branch oracle list, so nobody saw it.
