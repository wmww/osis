# eph-delete-loop
- Test helpers: no `Engine::may_write` to assert a node's role on a group in node tests; dropped the assertion and relied on the group's grants.
- `new_thing` in osis-node common writes `t:reg.0` = "new", so a purge without a write over it reads the earlier value at a node that never held the purged body; easy to misread as a bug.
