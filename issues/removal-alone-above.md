# A removal gone alone still reaches things above the actor
> Summary: while a removal from A goes alone (Seal waits), the removed party keeps opening every thing G that A holds a role on, and a node that may rotate A rotates G sealing A at A's uncovered epoch (encrypting under it, spec/crypto.md §4), until A's rotation is made.
> Tags: security, keys, engine

Probe (review of depth0-hostile; `removal_goes_alone_while_seal_waits_spec_permissions_3` plus G
owned by a1 with A holding read on G): after a1 removes a2 from A alone, `ensure_rotated(G)` at
a1 rotates G and seals A at A's current keyset; a2 opens G's newest read epoch
(`openable` from a2's earlier secrets). Diff kept in the review's scratch dir; rebuild from this.

- Content of G under G's epoch is sealed to A's keyset a2 still opens: depth 0 says G never looks
  inside A, so this is the "role ends at once" claim failing above A, not a leak beyond main
  (where the removal itself waited and a2 stayed a member). Unstated in spec/permissions.md §3
  and spec/crypto.md §4 Seal's limit.
- G's rotation boxing A at an epoch of A that does not cover a departure a1 knows is encrypting
  under it (sealing to a KEM key derived from it): §4 forbids it to a node that may rotate A.
  `rotation::ensure_rotated_but` rotates holder actors first but goes on to G when A's rotation
  waits (`recipients` None, or no possession); `members::sealed` asks nothing about A's block.
  Pre-existing for possession and lacking-secret waits; the alone path makes it the usual case.

Choices (a rule decision): G's rotation, grant and re-seal boxing A wait while A is blocked for
the node (freezes G's rotations with A's, as Seal-waits already freezes A); or state the limit
(a2 opens what A holds until A rotates) and narrow the §4 rule. Also say which for writers that
may not rotate A: the code blocks every node on an uncovered departure (`blocked_roles_of`),
the spec only nodes that may rotate.
