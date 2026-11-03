# Import purge seed 86144: in-place un-merge keeps a purged value
> Summary: `order::arrival_order_purge_import_large_spec_commits_5` seed 86144 (default size, fails on main too) trips `unmerged_as_rebuilt`: the in-place un-merge keeps an imported origin write's value `v1` that a rebuild holds value-less. Release builds skip the check, so the state may show a purged value. Not shrunk.
> Tags: security, engine, retention, tests

Replay: `OSIS_ORDER_SEED=86144 OSIS_ORDER_SHRINK=0 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_purge_import_large_spec_commits_5` (drop `OSIS_ORDER_SHRINK=0` to shrink).

```
in place Some(Register { reset: None, write: Some(RegWrite { stamp: (111411200000000005, CCommitId(f654e841f65b2da3..):1), value: Some(Str("v1")) }) })
rebuilt  Some(Register { reset: None, write: Some(RegWrite { stamp: (111411200000000005, CCommitId(f654e841f65b2da3..):1), value: None }) })
```
on the copy's `t:reg.0` (`core/engine/src/apply/atomic.rs` `unmerged_as_rebuilt`). Unshrunk history:

`h = vec![Message { by: 0, t: 0, v: 0 }, Write { by: 1, t: 0, op: 0, k: 0, v: 1 }, Sync { from: 1, to: 0 }, Move { by: 0, t: 0 }, Reimport { by: 0, from: 0, copy: 1 }, Edge { by: 0, t: 1, holder: 1, role: Some(Admin) }, Edge { by: 0, t: 1, holder: 2, role: Some(Admin) }, Sync { from: 0, to: 1 }, Sync { from: 0, to: 2 }, Sync { from: 1, to: 0 }, Reimport { by: 0, from: 0, copy: 1 }, Sync { from: 1, to: 2 }, Write { by: 2, t: 1, op: 0, k: 0, v: 4 }, Edge { by: 0, t: 1, holder: 1, role: Some(Admin) }, PurgeImport { by: 2, t: 1, back: 1, reset: false }, PurgeImport { by: 2, t: 1, back: 1, reset: false }, PurgeImport { by: 1, t: 1, back: 0, reset: false }, Message { by: 0, t: 0, v: 3 }, Message { by: 0, t: 0, v: 1 }, Sync { from: 0, to: 1 }, Sync { from: 0, to: 1 }, Write { by: 2, t: 1, op: 0, k: 0, v: 9 }, Message { by: 0, t: 0, v: 7 }, Compact { by: 2, t: 1, op: 0 }, PurgeImport { by: 2, t: 1, back: 0, reset: false }, Sync { from: 2, to: 0 }, Demote { by: 2, t: 1, holder: 2, at: 0, to_read: false }, Edge { by: 0, t: 1, holder: 1, role: Some(Admin) }, Write { by: 2, t: 1, op: 0, k: 0, v: 9 }, Compact { by: 2, t: 1, op: 0 }, Demote { by: 1, t: 1, holder: 2, at: 2, to_read: true }, Demote { by: 1, t: 1, holder: 2, at: 2, to_read: false }, Sync { from: 2, to: 1 }, Advance { who: Some(1), ms: 305 }, Sync { from: 1, to: 2 }, Sync { from: 2, to: 1 }, PurgeImport { by: 2, t: 1, back: 0, reset: false }, Compact { by: 2, t: 1, op: 0 }, Compact { by: 1, t: 1, op: 0 }, Edge { by: 0, t: 1, holder: 1, role: Some(Admin) }]`
