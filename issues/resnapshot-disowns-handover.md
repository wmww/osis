# A roster re-snapshot disowns earlier hand-overs
> Summary: An epoch-start snapshot's roster answers authority for all earlier times, so after a device is removed and the actor re-snapshotted (as spec/permissions.md §6 recommends), hand-over records that device signed while legitimately an admin become invalid and their aliases break. Needs a rule for judging records against pre-snapshot history.
> Tags: permissions

Found by `tools/fixpoint` (`snapshot` mode, test `p_resnapshot_disowns_former_device_records`): 2.3% of valid records in random runs. Records are kept forever (spec/permissions.md §7), but the history that made their signer an admin is retired at compaction.

Candidate fixes:
- A roster snapshot keeps former members as edges with `until` = their removal time, at least those that signed a hand-over record the snapshotter knows (risk: a record it does not know still breaks; snapshots grow with device churn).
- A hand-over record carries a certificate copy of its signer's chain as of the record, judged against the snapshot only for later demotions (close to the rejected frozen certificate bundle, which let ex-devices hand things out forever; would need the demoter-frontier rule to still apply).
