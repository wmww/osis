# An expired membership stays in the group index
> Summary: Once an expiring membership passes its time, `members(g)` and `at(g, GROUP)` no longer list it, but `groups_of(t)` (engine `ix.groups`) still does, at least until the index is rebuilt at open. Found building `w.group(g).expires(e)`; the same through the old `place_expiring`. Sync follows that index for a thing's own aspects.
> Tags: engine, tests

Repro (`core/osis/tests/it`, `clock()`, `cfg`): add `t` to `me` with `w.group(me).expires(Expiry::In(60 s)).add(Member::Item(t))`, commit, `c.advance(61_000)`, `db.engine(|e| e.tick())`. `db.members(me)` has no `t`, `db.groups_of(t).item_of` has `me`, `within` too.

`ix.groups.set` runs from `atomic.rs` when `group.0` is written (`group_def`). Expiry seems not to reach it. Left to a change in the engine, which the owner work is rewriting. Assert `groups_of` in `api::membership_expires_item_or_subgroup_spec_commits_6` when fixed.
