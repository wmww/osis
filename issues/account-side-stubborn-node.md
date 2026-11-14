# A device left on the removed node's side keeps reopening epochs the removed node holds
> Summary: A node of P whose user stays on X's side (it took X's revocation first) keeps rotating, boxing X. At P's honest nodes each such rotation that disowns nothing of a taken revocation's line counts as an honest fork: an open head whose seed X holds, so X's writes there count until a merge joins it, and the next rotation of that device reopens one. Unbounded while that user does not switch: Tess's rule ("every node disregards the removed device", no unbounded stall on one device) is not met. roles-model `-- 8000 forks-stubborn` fails (settled heads boxed to X at A and T).
> Priority: normal
> Tags: perm, security, tess-call

## World (roles-model `forks` names)
1. A removes X. B, offline, takes X's revocation of A first (first-seen: it stays there, warned, as Tess asked).
2. B's first rotation after that supersedes A's line unnamed (it disowns it): A and T disregard it (spec/permissions.md §5.4, at odds with a taken revocation's line).
3. A answers by superseding B's line unnamed; B's next rotation, signed at B's own head, supersedes A's newest rotation unnamed but nothing on a taken revocation's line: A follows it, a head boxed to B and X (B's roster on its side). A merges it (it holds the seed); B disowns the merge; and so on while B's user does not switch.

## Why the simple fixes fail
- Treating a rotation that disowns any followed rotation as the other side (not only a taken revocation's line) splits honest nodes once B's user switches: A and B placed B's old-side rotation and the merge it disowned in different orders, so each disowns the other's next merge for good (`forks-stubborn` with that rule: honest-side nodes on different heads).
- A node of P cannot tell which nodes a rotation boxed (it sees only whether it was boxed itself, and the seed may arrive later).

## Direction
The device's side is visible to P's other nodes only through what its rotations supersede. A rule that reads B's side from its rotations' lines (e.g. a node's rotations count at P's other nodes only while its newest rotation disowns nothing they follow, with a switch shown by a rotation naming the taken line) needs modelling with switches first (`forks-stubborn`, and B switching after any number of rounds). Alternatively, Tess may accept: a device kept on the removed node's side by its user reopens the removed node's access at the account's other devices until that user switches (a stated limit, with the warning shown on both).
