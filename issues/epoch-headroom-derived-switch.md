# Epoch headroom strands non-owner members of things under a jumped owner
> Summary: once a writer of an owner jumps the owner's epochs to about 2^62 (allowed), a thing switching to secrets of its own rotates to owner n + 1 > 2^62; a member of the thing that holds no secret of the owner cannot establish that epoch (no derived epoch at n − 1 to satisfy headroom, by chain or snapshot), so it never writes there. Permanent for that owner: its honest rotations stay above 2^62.
> Tags: security, keys

Mechanism (spec/crypto.md §4 headroom, `RoleEpochs::within_headroom`): the switch commit supersedes nothing a non-owner member holds (no boxes or keyset before it), so its epoch is chain-ready at once, but above `MAX_FREE_N` it needs another established epoch at n − 1; the derived epochs are only established (`adopt_derived`) at nodes holding the owner's. Snapshots key the thing's history boxes from e1 up, never the derived base. Liveness only (nothing wrongly encrypted); needs a malicious writer of the owner first. No test yet.

Fix direction: a base a non-owner member can check, e.g. the owner's published `/keys` keyset epoch for the role counting as established for headroom alone; or a switch rotation not counting from the owner's n (spec change to §3 and supersession filtering by n).
