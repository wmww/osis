# osis-perm structural cleanups left over
> Summary: Larger simplifications of core/perm/src found in the perm-simplify review and not done (hot-path or wide refactors): walk state kept in two shapes, the placement fast path copying `Pass::change`, two encodings of the partition rule, long parameter lists.
> Tags: perm

- **Walk state twice**: `Pass` flattens `Walked` and `Rest` into its own fields; `Pass::resume`/`finish`/`shadow` move them back and forth. Holding a `Walked` in `Pass` would drop the conversions and let the edge-record steps live on `Walked`.
- **`Walked::place_plain` copies `Pass::change` (no audit) and `Pass::record`** on `Walked` with its own undo log (spliced in after). With the state in one shape (above) both could share one implementation that logs to a given `Vec<Undo>`. The `Own`/`KeyState` hand-off in `place_shadowed` is the same problem.
- **Partition rule twice**: `incremental::links` (region growth) and `update_region`'s unions encode what joins a component separately; `links` also follows the `until.node` of ledger entries without a frontier (a superset, so harmless now). One function yielding the unions would keep them in step. Changing what joins moves component roots (saved-walk keys), so do it with a cache format bump or not at all.
- **Long parameter lists**: `Walked::insert` (8), `place_shadowed` (13), `dependents` (13) under `too_many_arguments`; a placement context struct (input, items, dropped, epoch, the commit and its keys) would carry most of them.
- **`Timeline::extend` and `append` end alike** (take `Kept`, `walk::resume`, `from_kept`, debug `check_scratch`); a shared tail would remove about 15 lines.
- **`Items::list` is a 5-tuple** `(Point, u8, Tid, Tid, Item)` read as `a.0`..`a.4` in many places; a struct with named fields would read better.
