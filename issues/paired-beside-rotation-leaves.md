# A node re-granted beside a concurrent rotation leaves its account
> Summary: a node off D's roster leaves only when a counting rotation carries a removal of it (`signing::leave_if_removed`), so a node paired beside a rotation whose list does not name its grant stays; still, a node removed earlier and granted again leaves on an unnamed re-grant, as the old removal's carrier counts. Custody's (e) closes it.
> Priority: normal
> Tags: engine

- Shape: node 0 grants node 2 on D while node 1, not holding that grant, rotates; node 2 takes node 1's rotation with its D list and reads itself off D's roster until node 0's listing names the grant. Unnamed is not removed.
- Interim rule (spec/permissions.md §3): leave only off the roster and with a counting carrier of a removal of this node (judged: minter signed it at the epoch it rotates). Tests: engine `rotation::tests_signing::a_node_paired_beside_a_concurrent_rotation_stays_*`, `a_header_naming_a_removal_its_minter_did_not_make_removes_no_one_*`.
- Remaining limit: the same shape for a re-grant after an earlier removal of the node: the earlier carrier still counts, so the node leaves for good.
- Custody's rule (e) (notes/account-forks-design.md Custody: a counting rotation superseding an epoch the node held, with no box to its device key) closes it; check (e) against this shape, not only the removed-node one (issues/sibling-removal-rotation-before-list.md).
