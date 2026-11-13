# A node can extend an account's line past a removal it does not hold
> Summary: an account epoch covers a removal from D by descent from an authorized rotation naming it (`rotation::uncovered`). A node holding a rotation r's seed without a removal r's line names (D's epoch r's seed sits under held for reading only: its names unmet) can rotate the account descending from r, sealing the new seed under its newest established D epoch, which boxes the removed node; knowing nodes credit the new epoch by descent.
> Priority: normal
> Tags: security, keys, engine

## Shape
N1 removes Y (r0 names it), then L (r1; its D epoch E1 names both). N2 holds E1's commit and a later D epoch's history carrying E1, but not Y's removal: E1 is not established there, yet opens r1's seed for reading. N2 rotates the account from r1 (for another removal), its seed under N2's D epoch boxing Y. N3, knowing Y's removal, finds Y named on the new epoch's line and writes under epochs boxing the account there. Model: `Account.tla` `Acc_nomet` (Met = FALSE) fails `NoLeak`; with Met it passes.

## Options
- Take up a seed (`signing::take_seeds`) only from an `account.0` section opened under an established D epoch: the "uses only established epochs" rule applied to seeds. Then a node descends from r only holding every removal D's epoch under r's seed names, which is the model's `Met` (`Acc_descent` passes with it). Needs the opening secret's epoch, which `Envelope::open` drops, kept per account rotation (a re-placed copy is sealed under the placer's epoch, so judge what this node opened).
- `rotate_in` waits until every D commit named on the line it extends is held. Cost O(names on the line) per rotation (rare); a named commit a node never gets stalls its rotations, and a namer since removed is not authorized but still held the removal its seed's D epoch names.
