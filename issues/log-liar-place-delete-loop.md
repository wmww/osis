# A host lying in its log keeps two writers placing and deleting a body
> Summary: a host that never lists a co-writer's covering snapshot to one node (a consistent lie in its own log, `Stream::seq` in order) keeps that writer re-placing a body the co-writer deletes, one round trip per turn, for as long as the host lies. Not measured: whether each turn grows either writer's store (fresh body, tombstone).
> Priority: low
> Tags: security, sync

- Found reviewing storm-489005 (numbered pushes fix the lost-push case only; notes/peers.md, Pushes in order).
- To check: per-turn growth at the writers (notes "no per-session growth" rule); whether the claimed equivalence with a host announcing deletes holds; whether the re-placing writer could judge a covering snapshot it cannot see by other means (the co-writer's delete carries its reason?).
