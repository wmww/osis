# Frontier listing leftovers
> Summary: Content commits write in session form, demotion frontiers list commit IDs only, snapshot frontiers list only traced sessions, and a commit whose parts all dropped as covered (any writer's cover) or purged is forgotten (built; spec/crdt.md §2.1, §8, spec/permissions.md §5.1, spec/commits.md §5 Forgetting). Left: two frontier listing questions from step 1. The demoter compacting first is issues/drop-rejoin-robust.md item 7.
> Priority: normal
> Tags: engine, spec

## Decided (Tess)
- Demotion frontiers by commit ID (32 B per uncompacted commit of the removed node), with the double-removal residual: accepted. A frontier past `MAX_LIST_BYTES` (about 1.9 million commits) cannot be written: a stated limit (spec/requirements.md Cost; issues/long-aspect-cost.md).
- The demoter compacting before an explicit demotion: not built for now (nothing blinks out, frontiers stay bounded by compaction cadence); revisit if demotion frontiers measure large. It is drop-rejoin-robust item 7.

## Open from step 1
- A removed admin's rotation covered by a role snapshot loses its record of which commit started the key epoch: an extra safe rotation, not a hole. Simplest fix: always list role commits in a frontier.
- A commit whose held parts are covered is left out of a frontier even if it also touches a thing the demoter does not hold; spec/permissions.md §5.1 says it should be listed. notes/frontier-study.md's rule ("lists every received commit of X in scope that is not droppable now", heads per (aspect, node) for permanent aspects) would settle both.
