# The public as a holder: requirements wording
> Summary: Build: a may-grant holder may grant the public (Tess: drop the special case); spec/permissions.md §2 (May-grant) to read the public as any holder, within the public's own cap (at most read, no may-grant flag).
> Priority: normal
> Tags: spec, perm

Wording settled (Tess): roles are held by a thing, a signing key or the public, and any role can be changed or removed (spec/requirements.md Concepts, Permissions). Adminless things, where nobody can revoke, are accepted: they follow from the rules.

## Related: may-grant to the public
spec/permissions.md §2 May-grant grant applies to "a grant for a thing or key", so a may-grant holder cannot grant the public read (make a thing public); only a path giving admin can. Reading the public as any holder there ("every other rule reads its grant as any grant") would let a may-grant reader publish what it may already hand to any number of readers. Decided (Tess): drop the special case, so the public is read as any holder there, within its cap.

