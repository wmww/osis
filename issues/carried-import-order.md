# Carried writes of a moved thing depend on arrival order
> Summary: A snapshot of a moved thing carries writes sourced as their origin commits; the carried index (`Core::carried`) keeps or drops them depending on whether the origin commit (held on the old thing) arrived before the snapshot, so a rebuild disagrees with the running node.
> Tags: node, validity, tests

Found by `walks::open_equals_rebuild_random_histories` (seeds 261 and 377: `OSIS_WALKS_START=261 OSIS_WALKS_SEEDS=1`), also on main before node-open-view. States agree; `carried` differs.

Case: thing `t` moved to `copy`; a snapshot of `copy`'s `/t/tags` carries a write with source `Commit(o)`, `o` a node-form commit on `t` (an import's origin).
- Running node, snapshot first, `o` later: `carried_of` keeps it (`o` not held); `uncarry(o)` looks only at `o`'s own aspects (`t`), and node form, so the entry on `copy` stays.
- Rebuild (or `o` first): `carried_of` skips it because `core.commits` holds `o`, though `o` owns nothing on `copy`.

`apply::validity::carried_of`'s commit-source rule ("a held commit owns it") should ask whether a held commit owns that write on this aspect: `o` itself only if it has the aspect, else a held import on the thing listing `o` in its origins; `uncarry` must then also run for an import's origins. Either way the result must be a function of the held set.
