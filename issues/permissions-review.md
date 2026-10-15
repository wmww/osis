# Review the permission model as a whole
> Summary: Walk notes/permissions.md end to end before implementation: hand-over adversarial scenarios, receipt-time rule details, witness roles, rotation cost, label entitlement, chat pattern limits. Requested by owner 2026-10-12.
> Tags: security, permissions, sync

Context: notes/permissions.md, notes/sync.md (Labeling, Authorization at blind nodes), notes/constraints.md (Permissions, tensions 1, 6, 7, 8, 9).

Review for consistency and gaps, then settle:
- Lazy hand-over is accepted conditionally. Walk it through adversarial scenarios (split at birth, repeated forks, chains of hand-overs, hand-over of an actor with members). Spec the derived-tid index and branch-relative resolution; check whether "standing in exactly one branch" is a sufficient decider for old references.
- When references are rewritten after a hand-over: at hand-over, on read, or on write. Includes `osis://` links inside markdown.
- Receipt-time rule details never discussed: validity as a least fixpoint over revokes and statements; what a re-grant does to never-witnessed writes; statement publication cost (one per aspect per author node a witness holds).
- Witnesses: statements are writes. Readers receive writes but cannot write to the actor thing, so either only writers witness, or statements are a special write any member may publish. Decide, and where statements live (actor thing, or the thing written).
- Label entitlement rule (2026-10-15, agent): an uploader wraps a thing's blobs for a label only if the label's actor may read the thing. Confirm with owner; check the shared-folder and chat patterns and the cost of the entitlement check at upload.
- One role on an actor covers both editing the actor thing's own data and acting as it. Confirm or split.
- Nesting cost: removing a member low in the hierarchy rotates read secrets of every actor it could read. Quantify and decide whether to mitigate.
- Per-role secrets and label-key derivation (proposal 2026-10-11): check against sharing, demotion, eager label re-registration and the mixed-owner chat pattern.
- Chat pattern limits left to app design (removed participant keeps control of old messages, no verifiable cutoff): confirm acceptable.
- Key recovery is out of scope (owner 2026-10-12); make sure nothing precludes it.
