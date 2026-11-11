# A writer reaching an actor only through a keyless grant is blocked as a rotator
> Summary: `departures::may_rotate` (blocking by stale or keyless boxes, `rotation_due`, re-seal scan) counts a role reached only through a keyless grant, but no rotation by it is valid (Possession: it never holds the holder actor's secret at the role needed); such a writer is blocked by a stale box like a rotator yet can never rotate, so it encrypts nothing under that role until a keyed rotator acts (a reader is not blocked at all).
> Priority: low
> Tags: keys

Seen in `tests_members::keyless_route_makes_no_valid_rotation_spec_crypto_4`'s shape (cycle G -> H -> M -> G; X writes M only through G's keyless grant on H). `members::may_rotate_keyed` is the role set that can make a valid rotation; spec/permissions.md §3 (Who rotates: through a holder actor only by showing it holds its keyset secret at the role needed) reads "may rotate" that way. Likely rule: one `may_rotate` = keyed roles everywhere the engine asks "may rotate". Cost to check: `roles_without` per call in `blocked_epoch`'s walk.
