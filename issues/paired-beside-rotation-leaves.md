# A node paired beside a concurrent rotation leaves its account
> Summary: node 0 pairs node 2 while node 1, not holding that grant, rotates P; node 2 takes the rotation with its D list, which names no grant of node 2, reads itself off D's roster and leaves for good (`signing::leave_if_removed`), though nothing removed it and node 0's listing would name the grant.
> Priority: critical
> Tags: engine

- Test: engine `rotation::tests_signing::a_node_paired_beside_a_concurrent_rotation_stays_*` (ignored, naming this issue). Pre-existing: the dropped removal clause of Waiting did not touch it.
- Cause: leaving reads D's roster as the epoch rule judges it, and a role commit on D the rotator never received is unnamed until a listing names it (Cutoff, Listings). Unnamed is not removed. Waiting does not cover it: the rotation's D list is held, so its epoch is decided.
- Fix direction: leave on evidence of removal only, as custody's rule (e) (notes/account-forks-design.md Custody: a counting rotation superseding an epoch the node held, with no box to its device key). Staying, node 2's own listing names the grant by the cutoff (it received it before the rotation), as node 0's does. Rule (e) must be checked against this shape, not only the removed-node one (issues/sibling-removal-rotation-before-list.md).
