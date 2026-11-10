# A node's writes at a removed node's concurrent rotation are lost
> Summary: node X rotates the account while node 0 removes it; sibling S gets X's rotation first and writes at its epoch (honestly: X is current in S's view). Node 0's merge rejects X's rotation (D's roster no longer holds X), so S's writes there count nowhere, S included, for good: no listing or list can name a commit at a void epoch.
> Priority: normal
> Tags: engine, perm, tess-call

## Shape
Engine probe (account-forks review): `world(4, 3)`; peer 2 `rotate_in`; peer 1 gets that rotation, writes, then gets peer 0's removal of peer 2; peer 0 merges (superseding peer 2's rotation unnamed). Every peer, peer 1 included, reads the write as never made. Same on main before the account-forks branch (a lone head was open there too).

## Why
- The merge names only heads a current node minted, so a removed node's fork falls with its lists (spec/permissions.md §5.5, Honest nodes of P). X's rotation made before its removal looks the same as one made after.
- The epoch rule names commits only at counting closed epochs (`osis_perm::Epochs::counts`); a rejected rotation's epoch does not count, so S's own listing cannot save them.

## Options
- A counting listing names its author's own commits at any held epoch (only nodes signing at the open epoch write one; a removed node's own fork listings stay void). Needs the epochs model first: X's later forks' lists would name its writes at void epochs too, within the fork window.
- The merge names a removed node's head when the merger received it before the removal (receipt is the merger's word, like the cutoff); S's writes then count by the merge.
- State it as a limit (requirements Permissions: an honest device's changes lost in a race with another device's removal).
