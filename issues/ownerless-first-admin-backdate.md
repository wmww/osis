# A removed admin can take a thing back by backdating
> Summary: A removed admin signs a removal of its remover stamped before that remover acted; the walk applies it and voids the remover's write. Every thing has this hole (admins are equal, the first admin included) until disputes are settled per node (notes/owner-removal-plan.md step 3, built next). Interim, stated.
> Tags: security, perm

n0 first admin, grants n1 at 1; n1 removes n0 at 10; n0 then signs "remove n1" stamped 5. Result: n0 admin, n1 out, also on things below (osis-perm, `scenarios::further_backdated_revoke_cancels`). n1 can answer stamped 3, n0 with 2; n1 cannot stamp before its own grant, so n0 wins the race. Frontiers do not help: n1's removal never applies, so it audits nothing.

Accounts included: a recovery key is an admin by a plain edge, so a stolen node that got there first can backdate its removal too. The design that settles it is notes/owners.md (option F: each node takes a side); nothing in the walk should try to.
