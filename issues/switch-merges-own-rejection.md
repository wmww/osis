# A node that switched sides merges its own rotation that rejected the line it switched to
> Summary: A node of P that took a removed node's revocation of A first supersedes A's line unnamed (a rejection). When its user later switches to A's removal, its next merge names that earlier rotation of its own, so every reader that followed A's line disregards the merge and all after it: the node's honest writes never count there. Found by roles-model `forks` with A rotating before it removes X (a generator dimension left out until this is fixed).
> Priority: normal
> Tags: perm, engine

## World (roles-model `forks` names)
1. A rotates (r1, at the first epoch), then removes X (r3, at r1). X, before receiving anything more, forks at the first epoch revoking A (r6).
2. B, offline, receives r1 and r6 at once; it takes X's revocation of A (first seen: r6 placed first), so r1 does not stand there, and B's rotation r14 (from its own fork r10) supersedes r1 unnamed: a rejection.
3. Settled: B's user switches to r3. B still follows r14 (its line stands: B is a node), and its merge r20 names r14.
4. R1, outside, follows A's line (r1, r3, ...): r20's line holds r14, which rejects r1, so R1 disregards r20 and every later merge. B's write at the first epoch, listed only at B's later epochs, never counts at R1.

## Direction
The merge carried in a rejection of the line the merger now follows. A node of P could withdraw instead: never name a head whose line rejects a rotation on its preferred head's line, and supersede it unnamed (its own listing saves its writes there). Then at the other nodes of P that rotation counts beside a later rotation of its own maker rejecting it (`forks` counts this as `View::cross`): decide whether a node of P drops a rotation its own minter rejects. Model first (`forks`: put A's rotation before the removal back in `random_world`).
