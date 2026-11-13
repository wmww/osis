# A node can extend an account's line past a removal it does not hold
> Summary: an account epoch covers a removal from D by descent from an authorized rotation naming it (`rotation::uncovered`). A node holding a rotation r's seed without a removal r's line names (D's epoch r's seed sits under held for reading only: its names unmet) can rotate the account descending from r, sealing the new seed under its newest established D epoch, which boxes the removed node; knowing nodes credit the new epoch by descent.
> Priority: normal
> Tags: security, keys, engine

## Shape
N1 removes Y (r0 names it), then L (r1; its D epoch E1 names both). N2 holds E1's commit and a later D epoch's history carrying E1, but not Y's removal: E1 is not established there, yet opens r1's seed for reading. N2 rotates the account from r1 (for another removal), its seed under N2's D epoch boxing Y. N3, knowing Y's removal, finds Y named on the new epoch's line and writes under epochs boxing the account there. Model: `Account.tla` `Acc_nomet` (Met = FALSE) fails `NoLeak`; with Met it passes. The order rule had the same hole (N2's clock is past r1's, so its epoch is ordered after Y's removal).

## Fix
Seeds follow "uses only established epochs": a node takes up an account seed only from an `account.0` entry it opened under a D read epoch established at it (its names met). Then it holds r's seed, and so can sign at r and rotate from it (`rotate_in` waits while the open epoch's seed is not here), only once it holds every removal D's epoch under r's seed names: the model's `Met`.
- Applying `account.0`: keep, per seed, the D epoch whose secret opened its entry (`Envelope::open` finds it by trial and drops it today). Judge what this node opened: a re-placed copy is sealed under the placer's epoch.
- `signing::take_seeds`: skip a seed whose opening D epoch is not established; re-run it when D's establishment moves (a removal arriving), as it runs when `account.0` moves.
- Test: the Shape above in osis-engine `rotation::tests_signing`; flip `Acc_nomet` to the stated property (Met is then the code's rule, so drop the control or keep it as a negative one).

Rejected: `rotate_in` waiting until every D commit named on the line it extends is held. O(names on the line) per rotation, a named commit a node never gets stalls its rotations, and a namer since removed is not authorized yet still held the removal its seed's D epoch names.
