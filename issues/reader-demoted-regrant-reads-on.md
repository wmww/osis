# An admin demoted to reader while re-granting leaves the grantee reading
> Summary: Accepted limit (Tess; kept out of spec/requirements.md): admin P, concurrently demoted to reader, re-grants removed reader X; wherever the demotion is held the grant is void, yet X keeps the key P gave it and reads new content until something else rotates read. Demoted to writer instead, the void grant counts and forces a rotation (spec/crypto.md §4 Covers). Fix only if a way without significant trade-offs appears.
> Priority: low
> Tags: security, keys

Test: `invalid_grant_box_judges_nothing_spec_crypto_4`; model: Cover.tla `C_regrant_reader` (fails `NoLeak`, run as the stated limit).

Known options, each with a trade-off: let readers' void re-grants force rotations (any reader then forces a rotation per junk commit, against "malicious readers can only waste storage"); one rotation per demotion instead of per write (needs a recursive rule over how P got its rights: notes/crypto.md, Frozen coverage, Rejected). P, still a reader, could hand X the key anyway.
