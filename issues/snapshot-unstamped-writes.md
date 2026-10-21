# Snapshot writes without a `ts`
> Summary: writes a compaction snapshot carries without their commit are judged at their own stamp's `ts`; element creations without a stamp borrow their node's nearest stamp below, and commit-form writes or creations with no stamp below are not judged at all.
> Tags: node, security

`apply::validity::carried_of` groups a snapshot's carried writes by (node, `ts`) with exact counters (an invalid group un-merges only those dots). An element creation carries no `ts` (spec/crdt.md: stamps carry one, element identities do not), so it joins the group of its node's stamp with the greatest counter group start at or below it. That `ts` is only a lower bound: a creation made after a demotion of its node can be judged at an earlier `ts` where the node still held write, and a hostile writer's snapshot can pair a victim's real (compacted) element with a forged older stamp to have it judged at that stamp's `ts`. The damage is bounded by what a writer may do anyway (delete elements), but it is not undoable like a delete.

Not judged (kept as valid): creations of a node with no carried stamp below them, and commit-form writes (no author named).

Options: spec a `ts` for element identities in snapshots (wire change), judge an unstamped creation at the snapshot's `ts` with the "held at some point before" rule, or treat unjudgeable writes as invalid (strips honest compacted texts and lists whose commits are gone).
