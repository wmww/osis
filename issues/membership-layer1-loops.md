# Layer-1 membership rule can loop forever
> Summary: The layer-1 validity rule as written (notes/permissions.md, Validity definition) has no stable answer for many histories, so its iteration never terminates; found by brute force in tools/fixpoint.
> Tags: permissions, security

## Rule checked
Order membership writes by (HLC, node), walk them applying each iff its author is admin at that point. A write by an actor not admin at the end must also be witnessed (received by a still-authorized node, directly or via a valid attestation) before its demotion time; drop the unwitnessed ones and walk again from "nobody revoked" until nothing changes.

## Method
`tools/fixpoint` (`cargo test` for scenarios, `cargo run --release [samples] as` for the search). Exhaustive up to 3 membership writes (owner, 2 admins, 1 writer, skewed receipt times, offline nodes), plus 20M random histories (up to 4 admins, 2 writers, 8 writes).

## Findings
- **No stable answer, iteration loops (period 2)** in 14% of random histories, 3-5% of exhaustive ones. Minimal cases:
  1. An admin removes itself; nobody receives it before its own timestamp. Applied, it is a removed actor's unwitnessed write, so it is dropped, so the actor is not removed, so it is applied again. One write suffices.
  2. A1 removes A2; only A2, the victim, receives it in time; later the owner removes A1. If the removal stands, A2 is removed and cannot witness it, so it is dropped; if dropped, A2 is a member and witnessed it. Same shape as a stolen device's backdated removal whose only receiver is its target.
- Exempting the removing write from its own judgment fixes case 1 only; about 1% of random histories still loop.
- **Several stable answers** in 1-2% of histories, e.g. mutual removal where neither removal was received in time is self-consistent either way. Iterating from "nobody revoked" picks the earlier removal, as intended. Uniqueness of the stable set therefore cannot be required; the rule's answer has to be defined as the output of a procedure, and that procedure must terminate.
- Input order never changed the result. Layer 2 (content given final membership) was monotone in receipts in every sample; layer 1 is not, inherently (a receipt that validates a revoke invalidates its target's later writes).
- Expected outcomes hold wherever the iteration terminates: mutual removal goes to the earlier timestamp, the owner's further-backdated revoke cancels a stolen device's backdated revokes, re-grant validates intermediate content, a cycle of removed witnesses validates nothing.

## Related observations
- Witnesses for membership writes are write+ nodes. A writer colluding with an ex-admin can therefore keep the ex-admin's backdated membership writes valid, i.e. jointly hold admin power neither has alone (the argument that excludes readers from witnessing content).
- Membership writes made in a revoked-then-re-granted actor's gap stay invalid (the walk skips them); only content is validated by a re-grant. Not stated in the notes.
- Any replacement rule changes who wins some contested admin conflicts, so the choice is the owner's. `tools/fixpoint` can compare candidate rules against the as-written one and the scenario tests.
