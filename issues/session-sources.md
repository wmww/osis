# Frontier listing leftovers
> Summary: Two demotion-frontier listing gaps: a removed admin's rotation covered by a role snapshot loses which commit started its epoch (an extra safe rotation), and a commit whose held parts are covered is left out of a frontier though spec/permissions.md §5.1 lists it. Tess's decisions on frontier form below; the demoter compacting first is issues/drop-rejoin-robust.md item 7.
> Priority: normal
> Tags: engine, spec

## Decided (Tess)
- Demotion frontiers by commit ID (32 B per uncompacted commit of the removed node), with the double-removal residual: accepted. A frontier past `MAX_LIST_BYTES` (about 1.9 million commits) cannot be written: a stated limit (spec/requirements.md Cost; issues/long-aspect-cost.md).
- The demoter compacting before an explicit demotion: not built (nothing blinks out, frontiers stay bounded by compaction cadence); revisit if demotion frontiers measure large.

## Open
- A removed admin's rotation covered by a role snapshot loses its record of which commit started the key epoch: an extra safe rotation, not a hole. Simplest fix: always list role commits in a frontier.
- A commit whose held parts are covered is left out of a frontier even if it also touches a thing the demoter does not hold; spec/permissions.md §5.1 says it should be listed. notes/frontier-study.md's rule ("lists every received commit of X in scope that is not droppable now", heads per (aspect, node) for permanent aspects) would settle both.
