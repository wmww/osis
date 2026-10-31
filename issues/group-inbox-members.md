# A group's non-admin members learn of its edges only through its labels
> Summary: an inbox blob for group G (its inbox is its owner's home label) reaches only G's admins, and the copy they place goes under that home label, not G's own; so G's other members never learn a grant of G on a thing outside G's closure, and learn a removal of G's edge only when its author syncs a label holding G. Members that disagree on G's edge can storm.
> Tags: permissions, sync

Found fixing the explicit-removal case (tied.rs `group_members_learn_edge_removal`, `inherited_inbox_opens`).

- Grant: Bob grants tag G (Alice's, Carol a writer) read on Bob's own tag T. Alice opens the inbox blob and syncs T; Carol never hears of it. `inbox_copies` places the copy under the inbox label (Alice's home), which Carol does not read. spec/sync.md §3 says the copy goes under "that actor's home label"; for G that is G's own label.
- Removal: a removal of G's edge is placed under the labels holding G that its author syncs (spec/permissions.md §2). An author syncing none (an admin of the target through another group; probe: Dave, admin of Bob's card through tag H, removes G's edge on a card placed in G and H) also usually lacks G's `/keys` (`deliver_parts` finds no keyset), so nobody in G learns; G's members keep the edge. Stale but consistent.
- Storm: when G's admins learn a removal and the other members do not, the admins delete the target's bodies under G's label as `Outside` and stale members upload fresh encryptions of them again, forever (seen with the inbox fix and without the removal placement: `share_into_unplace_and_stale_placement` never settled). Placing the inbox copy under G's own label (first bullet) would close both.
