# Review the permission model as a whole
> Summary: Walk the permission design (notes/permissions.md) end to end before implementation: hand-over adversarial scenarios, receipt-time rule details, role semantics, rotation cost, chat pattern limits. Requested by owner 2026-10-12.
> Tags: security, permissions, sync

Context: notes/permissions.md, notes/sync.md (Authorization at blind nodes), notes/constraints.md (Permissions, tensions 1, 6, 7, 8, 9).

Review as a whole for consistency and gaps, then settle the listed open points:
- Lazy hand-over is accepted conditionally. Walk it through adversarial scenarios (split at birth, repeated forks, chains of hand-overs, hand-over of an actor with members). Spec the derived-tid index and branch-relative resolution; check whether "standing in exactly one branch" is a sufficient decider for old references.
- When references are rewritten after a hand-over: at hand-over, on read, or on write. Includes `osis://` links inside markdown.
- Receipt-time rule details never discussed: validity as a least fixpoint over revokes and statements; what a re-grant does to never-witnessed writes; statement publication cost.
- One role on an actor covers both editing the actor thing's own data and acting as it. Confirm or split.
- Nesting cost: removing a member low in the hierarchy rotates read keys of every actor above. Quantify and decide whether to mitigate.
- Per-role secrets and label-key derivation (proposal 2026-10-11): check against sharing, demotion, eager label re-registration and the mixed-owner chat pattern.
- Chat pattern limits left to app design (removed participant keeps control of old messages, no verifiable cutoff): confirm acceptable.
- Key recovery is out of scope (product decision, owner 2026-10-12); make sure nothing in the architecture precludes it.
