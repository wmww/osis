# Key access ignores the path through a destroyed actor
> Summary: `Core::key_holders` puts a destroyed holder actor t's frozen holders in its place on A, but key access (`members::keyed`, `osis_keys::key_access`) judges only grants: a frozen holder m reached through t has no grant on A, so it always counts as keyed, even where the grant (A, t) or (t, m) was the keyless one of a cycle. A then boxes m and can close the key cycle the keyless grant broke (spec/crypto.md §4, key access; Limit on cycles).
> Priority: normal
> Tags: security, keys, engine

- Case: x holds g (g's grant on x), g holds t (destroyed), t holds... concretely grants (g, x) and (t, g) keyed first, (x, t) judged keyless last; after t is destroyed, x boxes t's frozen holder g directly (no grant (x, g), so keyed), while g boxes x: a cycle x -> g -> x of boxes, where a party removed from one may open the other's epochs so sealed.
- Not modelled: Depth0's destroyed configs have no cycles (`Hidden = {}`).
- Direction: an expanded holder is keyed only if every grant on its path is (the key analogue of "the lesser role along the way"): judge it inside `expand_destroyed`, or feed `key_access` a grant (A, m) per expansion ordered after both links. Receivers' possession (`holder_actors`) must then expand the same way, or a sender skipping m and a receiver requiring m's proof disagree.
