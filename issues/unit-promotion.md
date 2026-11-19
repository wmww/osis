# Promotion under the sync unit design: three cases that lose or strand content
> Summary: held-model `spec_unit` models promotion (notes/sync-unit-design.md §5). The carrier rule, the late writer, P late, a mixed commit, a dispute over P, a removal on its way and the work hold; three cases fail: a promotion drops what H's unit reached past X, a promotion judged invalid strands what was written under S(X), and a node syncing X by the lesser sync ID of a forked promotion never learns the greater. Each with its smallest world and the ways out seen; B1 should not build §5 before one is chosen for each.
> Priority: normal
> Tags: sync, engine

## 1. A promotion drops what H's unit reached past X
Contradicts spec/permissions.md §3 Own secrets add only ("a thing becoming independent changes in no way who reaches it ... every sync ID that carried the thing keeps carrying it") and design §5 "X and the dependents whose independent it becomes move from H's unit to X's", §2 "It does not go stale in a way that matters".

X is a dependent of H, Z a dependent of X. A unit is its independent thing and the dependents it reaches (§6). After X is promoted, Z belongs to X's unit only if X's unit reaches Z.
- H -> X, H -> Z: Z is in no unit after. Every holder loses Z (`promotion_moves_x_and_what_x_reaches`).
- H -> Z -> X: Z is in no unit, and X's handle is in no unit H's holders enter: they lose X and Z.
- H -> Z, X -> Z, X unreached before: Z moves into X's unit, which H's holders never enter (the strong's home names H, X's handle is nowhere).
- A referrer G -> Z with home H depends on H's unit referencing X itself.

Ways out:
- **The promoter keeps the reach**: in P's transaction, for each thing of X's subtree that H's unit reaches and X's unit does not, it adds a strong from X (or promotes that thing too), and re-homes H's strongs into X's subtree (a new dot of the same value, home X). It holds all of H's unit, so it can. What a concurrent writer lacking P adds afterwards is the accepted cost of §6 (a strong to a dependent its unit does not reach brings nothing). Adds work in the number of such strongs, at the promotion only.
- **A dependent stays with each unit up its chain that reaches it** (Z under S(H) and S(X) while both reach it): every reader computes it, but a write on Z is entered once per unit again, the cost the design removes.
- **Refuse the promotion** locally while it would leave a dependent unreached (the making rule's way): no rule every node judges, and concurrent writes still reach the state.

## 2. A promotion judged invalid strands what was written under S(X)
Contradicts design §5 "a node keeping the closure unread always holds X's content under one of the two" and the open item "moves the bodies back".

H, X its dependent, H -> X; writers A and B of both; a keeper of H (`a_voided_promotion_strands_what_was_written_under_x`). P stands; A writes a body of X, under S(X) alone. The void (a removal of P's author, say) reaches B first: X is H's again by B's view, so B deletes X's key and handle at S(H) and never syncs S(X) again (no view holding the void has that sync ID). The keeper drops S(X) and holds the body nowhere. Only a node holding the body (A, once it has the void) logs it under S(H); no node counting P invalid passes S(X), so a body only S(X)'s stores hold stays there for good. The every-order runs of P, a body and the void reach it too.

Ways out:
- **A writer holding the void passes S(X) for the errand** (as design §12 case 3 holds a unit for an errand): it pulls S(X), logs X's bodies under S(H) by the carrier rule, and keeps X's key and handle at S(H) while S(X) holds a body S(H) lacks. Needs the voided sync ID kept as a unit to sweep, with its own end.
- **A sync ID once created stays the thing's unit** (spec/sync-ids.md §2 already says "for its life"): an invalid promotion changes X's keys back to derived ones but not its placement, so nothing moves back. Then validity of P's keys and P's placement part ways; a node counting P invalid still syncs S(X).

## 3. A node syncing X by the lesser sync ID of a forked promotion never learns the greater
Contradicts nothing written: design §2 Key blobs ("each owned one after a forked promotion") serves nodes entering X through a key blob; spec/sync-inbox.md §5 Ticket sync IDs has a node sync the greatest sync ID a held `sync.0` records.

H, X its dependent; two promotions at once; C syncs X alone and holds the first promotion only (`forked_promotions_name_both_sync_ids`). Writers holding both put everything of X under the greater sync ID and the second promotion under S(H) and that one; nothing goes under the lesser. C never learns the greater sync ID and holds X frozen. Nodes entering through S(H) are fine: the key blob names both, the keeper of H enters both, X's bodies settle under the greater.

Ways out:
- **X's `sync.0` writes go under every sync ID X owns** (role entries of each): a node at the lesser learns the greater and moves. One entry per extra sync ID per promotion.
- **The ticket names the greater**: the grant's issuer re-fires C's ticket at the greater sync ID once it holds both (spec/sync-inbox.md §5 Key changes already fires fresh tickets at a rotation).
