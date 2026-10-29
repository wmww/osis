# Dropping a valid carrier lets an invalid copy void the write
> Summary: a write held only through snapshots stays valid while one valid carrier's body is held; once that body drops (keep at most, covered), an invalid carrier's copy (a reader's or a demoted writer's snapshot) makes it carried-invalid: un-merged at once if the invalid snapshot arrives after the drop, kept in the state (until the next rebuild of the aspect) if it arrived before. Order-dependent state, and a reader can remove others' writes at nodes that dropped the valid carrier.
> Tags: security, node, retention

Test: `validity::valid_carrier_dropped_alike_either_order_spec_perm_5_2` (ignored on this issue): Bob's tag carried by Alice's valid snapshot S and a reader's forged one R, Bob's commit never held; R then drop S keeps `{bob}`, drop S then R gives `{}`.

Cause: `forget_snapshot` (on `drop_part`) removes S's carried groups (`Core::carried` is derived from bodies, so an index rebuild at open cannot restore them either); `carried_bad` then counts only R's invalid group. The un-merge rule (spec/crdt.md §4.6: the current state counts as a held snapshot, so live writes of dropped bodies survive; spec/permissions.md §5.2: one carrier's bad copy never voids another's) says the write stays.

Fix sketch: keep a dropped valid snapshot's carried groups as givers (persisted beside `Meta::live_drops`, re-judged on flips like any group), or record per aspect the carried dots validly given when a carrier dropped. Un-merging on drop instead would be order-independent but makes the reader attack work everywhere.
