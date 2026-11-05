# A reader forces a rotation per junk commit (held boxes)
> Summary: since held boxes count invalid `secrets.0` deltas, a reader of A writing junk boxes (invalid: it lacks write) makes A's rotators rotate once per commit, unbounded; it gains no secret it lacked.
> Tags: security, keys, engine

Held boxes (spec/crypto.md §4) judge the boxes of every held invalid `secrets.0` delta, so the
honest case (an admin demoted concurrently boxes a party that then holds no role) is rotated
away. But any author whose delta is held counts. A reader of G that copies its own box under a
key naming a party with no role, at G's current read epoch, is a departure no epoch covers: G's
admin is blocked on read and rotates. Repeat: one rotation per reader commit, unbounded (probe
in review of e24b3a6e6: 5 junk commits, 5 rotations; 0 with held boxes limited to the state).
Through a holder actor M it cascades: a junk box in M's `secrets.0` re-keys M, which makes every
A holding M stale.

The rotation buys nothing against that reader (it holds the new epoch too and can hand it on);
it only protects boxes written honestly by an author who lost its role concurrently.

Possible rule: an invalid delta's boxes count only when its judgment names a demotion
(spec/commits.md §5, an invalid delta's fall; the author held the role it needed and lost it).
A former writer can still spam deltas concurrent with its demotion. Needs a model run
(`D0_box_see`) and the cycle harness at full size.
