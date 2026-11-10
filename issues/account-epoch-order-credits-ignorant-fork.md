# An account epoch is judged by order, so an ignorant fork ordered after a removal passes
> Summary: at an account's own nodes an account epoch counts as covering a node's removal from its devices actor when its rotation is ordered after the removal (`rotation::uncovered`, `AccountView::minted_before`). Order is not knowledge: a concurrent account rotation by a node that did not hold the removal, with a later clock, sealed its seed under D's epoch the removed node opens, and the knowing nodes still write under epochs boxing the account there until the merge reaches the boxing actor's admin.
> Priority: normal
> Tags: security, keys, engine

## Shape
Carol's nodes N1, N2, lost node L. N1 removes L (D's rotation, then P's rotation r1). N2, not
holding that yet, removes another node Y: D's rotation boxing L, then P's rotation r2 whose seed
goes into D's `account.0` under that D epoch, so L opens r2's seed. r2's HLC point is after L's
removal. Team T (another account's) boxes P at r2's epoch; X (Carol's) boxes T. At N3, holding the
removal and r1, r2's epoch is minted after the removal, so X's epoch boxing T at a keyset boxing P
at r2's epoch is not blocked, and N3 writes X content L opens, until the merge of r1 and r2 makes
T's box to P stale and T's admin rotates.

## Options
- Judge an account epoch by what opens its seed: the D epoch its `account.0` entry was encrypted
  under, by D's own coverage (D has history). One mechanism: the account's seed is a box to D.
- Judge by descent: an epoch covers a removal iff it is, or descends from, a counting rotation
  whose thing list for D names the removal (every counting removal is named by one:
  `signing::rotations_due`). Descent reads the chain, so it needs an index to stay off O(chain).
- Stated limit (today): the ignorant-rotation limit (notes/crypto.md, Limits) reaching a knowing
  writer while the account's forks stand.
