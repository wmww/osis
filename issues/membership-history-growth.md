# Membership history and attestations can never be compacted
> Summary: The demoter-frontier timeline is a function of every membership write of an actor and content validity needs attestations forever, so certificate sets grow without bound and violate "nothing depends on retaining full history"; recorded as constraints tension 12 with a roster-snapshot proposal.
> Tags: permissions, sync, scale

Review 2026-10-16. Every verifier of writes under an actor downloads and walks that actor's whole membership history (about 300 bytes per write, O(n) per re-evaluation). Fine for v1 sizes; wrong in the long run for busy organizations.

Proposal (notes/permissions.md Open): a roster snapshot, a membership write by an admin at T re-granting the whole current roster with its embedded frontier, from which every node starts the timeline; certificates older than the newest applied snapshot become droppable. Sound under the existing trust model (an admin can already grant anyone), but it must be run through tools/fixpoint before adoption, and the interaction with sticky drops and with snapshots by later-demoted admins needs checking.

Owner call: accept unbounded growth for v1 (current call) or spec the snapshot now, while the timeline rule is fresh.

## Owner snapshot (owner's idea 2026-10-16, preferred over admin snapshots)
The owner's authority is in the tid, so an owner-signed roster snapshot at T verifies standalone: no snapshot chain, and a snapshot by the top key actor can never be dropped (it owns itself). Verifiers start the timeline at the newest owner snapshot; older certificates retire after a horizon, so removed members' records disappear (erasure). Content: a compaction snapshot by an authorized writer carries its elements on that writer's authority, so attestations retire with the commits they cover.
Remaining, none unsound: person-owned things are in practice snapshotted by the person's devices (the recovery key is offline), which a later backdated removal of that device can drop; the failure shrinks the roster toward owner-only, never widens it, recourse is a fresh snapshot plus re-grant. Pre-snapshot writes arriving after compaction are invalid, so compaction trades "no finality" for a horizon. Only the owner chain compacts.
Before adoption run tools/fixpoint on: owner snapshot then churn; stolen device's snapshot undone by a backdated removal; late pre-snapshot grant.
