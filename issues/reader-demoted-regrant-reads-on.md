# An admin demoted to reader while re-granting leaves the grantee reading
> Summary: Admin P, concurrently demoted to reader, re-grants removed reader X: wherever the demotion is held the grant is invalid, yet X keeps reading the actor's new content until something else rotates read. Demoted to writer instead, the same grant forces a rotation (spec/crypto.md §4, Lowering): whether X keeps reading depends on which role P was demoted to. Closing it lets readers force rotations. Needs Tess.
> Priority: low
> Tags: security, keys

Test: `invalid_grant_box_judges_nothing_spec_crypto_4`; model: Cover.tla `C_regrant_reader` (fails `NoLeak`, listed as the limit).

## For Tess
An admin removes reader X; at the same time another admin demotes admin P to reader, and P, not yet knowing, adds X back. Everyone who sees the demotion treats P's re-add as void, but P already gave X the current key, and nodes that saw P's re-add first may give X later keys too. Nothing changes the read key afterwards, so X keeps reading new content until some unrelated key change. If P was demoted to writer instead, the void re-add counts as a fresh removal of X and the key changes. We can't do the same for readers: then any reader could force a key change with every junk commit it sends ("malicious readers can only waste storage"). The only bounded fix found is one key change per demotion instead of per write, which needs a recursive rule over how P got its rights (notes/crypto.md, Frozen coverage, Rejected). P, still a reader, could hand X the key anyway. Options: (a) accept it and state it in spec/requirements.md as a limit: an admin demoted to reader while re-adding someone gives them read access until the next key change; (b) let readers' void re-adds force key changes, so a reader can make writers rotate once per junk commit; (c) build the recursive per-demotion rule.

## Decision
Tess: accepted as a limit for now. Not stated in spec/requirements.md; fix it if a way without significant tradeoffs appears.
