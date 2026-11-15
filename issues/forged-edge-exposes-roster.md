# A writer's invalid grant makes honest nodes log another actor's roster
> Summary: chain certificates follow "ever" paths (perm `Input::ever`: every held edge write, valid or not), so a writer of S's thing T that is no admin can write an invalid grant of private actor Y on T; every honest node holding Y's roster then logs it under S (`Piece::Own`: every actor's chain into T, `Timeline::certificates_into`), past spec/requirements.md's "roster of every actor holding a role on it".
> Priority: normal
> Tags: security, sync, perm

Found reviewing the acting chain (`Indexes::chains_on`), not reproduced in a test. The same superset reaches `Piece::Chain(X, Y)` for a commit of X acting for Y: with X never on Y's roster it carries Y's record chain and card (Y's first admins); with X forging an edge write on Y (held where Y is) it carries the edges among X and Y. Strictly less than the grant case above.

The "ever" superset exists so a chain needs no replay (perm cert.rs). Options: build `ever` from edge writes whose author is a possible admin of the target (`Held::ever_admins`, monotone and forger-proof), or of an invite holder there for invite grants; check that every walk's paths still lie inside it. Test first: a non-admin writer of T grants private Y on T; a node reading S and Y logs nothing of Y's roster under S.
