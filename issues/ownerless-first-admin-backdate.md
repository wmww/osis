# A removed first admin can take an ownerless thing back
> Summary: On an ownerless thing, a removed admin signs a removal of its remover stamped before that remover acted; the walk applies it and voids the remover's write. So hand-off is not final and the first admin is a hidden owner.
> Tags: security, perm

n0 first admin, grants n1 at 1; n1 removes n0 at 10; n0 then signs "remove n1" stamped 5. Result: n0 admin, n1 out, also on things below (osis-perm probe, `World::set` as in `scenarios::ownerless_has_no_owner_chain`). n1 can answer stamped 3, n0 with 2; n1 cannot stamp before its own grant, so n0 wins the race. Frontiers do not help: n1's removal never applies, so it audits nothing.

The same holds between edge admins of an owned thing, but there the owner settles it (its removal drops the unlisted write). An ownerless thing has nobody to do that. Any fix is a design choice: notes/owners.md.
