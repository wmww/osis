# Authority accepts a proof of a holder actor at any rotated role
> Summary: a rotation of A shows holder actor H by a proof at any rotated role (members::authority, spec/crypto.md §4 Possession "shows"), so a party holding write on A only through H but H's read secret only makes valid read+write rotations of A, and its write-only rotation is invalid; the right to rotate is proved at a lower role than the one it runs through.
> Priority: normal
> Tags: security, keys

`members::authority` counts H shown when any rotated role r <= H's role on A carries a symmetric box under H's secret; the spec's "shows" names no role. The right needed for any rotation is write or above, so a proof at read says nothing about the role the rotator's path through H needs.

Effects:
- Possession weakened: X demoted on H from write to read (H rotates write, not read) still holds H's current read keyset. At a node not yet holding the demotion, X's read+write rotation of A (A holding H at write) shows H and is valid, so X boxes itself A's new write secret and its writers encrypt write-level material to it until that node learns the demotion. Possession exists to close exactly that window.
- Inconsistent validity by role set: X reaching A's write only through a keyless grant on H (cycle G -> H -> M -> G, `merger_holds_its_role_over_keyed_grants_spec_crypto_4`) makes valid read+write rotations of M but never a valid write-only one. The Merger rule (`may_rotate_keyed`) excludes such a maker, but `rotation_due` still lets it try (`may_rotate`), and a fork whose only remaining rotators reach the role through keyless grants stays forked whenever its merge rotates write without read.

Likely rule: a rotation shows H only by a proof at the role its rotator needs through H (the rotation's right, write or admin). Then `may_rotate_keyed` is "may make a valid rotation" and could replace `may_rotate` in `rotation_due` too. Touches osis_keys::rotate (proofs per rotated role), apply/validity.rs, spec/crypto.md §4 Possession.
