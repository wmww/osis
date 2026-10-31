# Sharing through a group: tie the role grant to the placement
> Summary: sharing what is in a group is today two untied records (the placement on the group, a role grant on each member thing), and apps cannot keep them in step. Proposal: keep both records where they are, mark a grant as **tied** to the placement that made it, write both in one commit, and make the grant's removal after an unplace a core obligation (like link finalization). Rejected: "placement grants access" (the rights record would leave the thing, so its admins could no longer see or revoke shares). Also found: pain point 3 is an API gap (no call for a group's admin to self-remove the group's edge). Owner call on the open decisions at the end.
> Tags: permissions, crypto, api

Terms (owner decision, rename pending in issues/rename-roles-members.md): a **role grant** or **edge** is the rights record (actor, target, role; today `/members`); a thing is a **member of a group** when the group's `/group` lists it (a **placement**). A tag is a group with `/tag`; nothing here depends on that.

## Current design (notes/tags.md "Sharing a tag")
The group G becomes an actor. Each member thing T gets an edge (G, T, role) written on T; a member group gets one too, so access chains down (T → U → item, role = min along the path). Adding is "place, then grant"; removing is "unplace, then revoke". Owner, then: no helper, "place plus grant is the operation".

## Why it fails in practice (the app prototype built it; its buggiest code, since removed)
1. Two commits, synced separately: a device that sees the placement but not the grant and unplaces leaves the grant behind; a grant can arrive after an unplace that never saw it.
2. No provenance: a grant made by placing cannot be told from a hand share, so an unplace may revoke a hand share.
3. Someone unplacing my thing from their group cannot revoke their group's edge on it. **Correction**: the spec allows it (spec/permissions.md §2 self-removal: admin on actor G may always remove G's edge on any target), but the API does not: `demote` needs admin on the target and `leave` removes only this person's own edge. An API gap, not a design gap.
4. Revocation becomes app work: a durable queue, retries, deciding whether it is still needed.
Root cause: the two records are not tied, so no app can make them one unit.

## Rejected: placement grants access
The proposal first considered: a group's role holders get their roles on every member thing, the placement being the grant. It gives the right feel (one op to add, one to remove) but moves the rights record off the thing, and that breaks things that matter more:
- **The thing's admins lose sight and control of its shares.** Alice (admin of her note N) places N into Bob's shared tag H, being a writer of H. Bob removes Alice from H. Alice can no longer write H, so she cannot unplace N; H's members keep reading N and nothing on N lets Alice stop it. Today she revokes H's edge on N. Any fix needs a durable "not this group" record on N, which is an edge on N: `/members` rebuilt under another name. Invariant to keep: **the authoritative rights record on T lives on T** (or its owner chain), so T's admins can enumerate and revoke every share.
- **Placements become rights writes.** A verifier of a write on T through G must check that T's placement into G was made by someone who could share T at that time. So `/group` item writes join the membership timeline (spec/permissions.md §5.1) as cross-thing edge writes: frontiers must cover `/group` on groups the demoter may not hold, chain certificates get a new link type (a `/group` write projected to one item), and the highest-churn aspect we have, with an ephemeral side, enters the walk whose cost is already an issue (issues/perm-eval-cost.md).
- **Readers may tag what they cannot write** (owner decision, notes/tags.md: placement is the tag's data, so tags of a shared thing stay private). Under the proposal such a placement must be judged "a member but grants nothing" by the placer's authority on T, so two classes of placement exist anyway, told apart only by a timeline judgment.
- It contradicts spec/requirements.md Permissions "Grouping for sync grants no rights" and gains nothing over the tied design below: the keys (T's secrets boxed to G in T's `/secrets`) are the same, the rotations are the same.

## Proposal: tied grants
Keep placement (on G, write on G, organizes and syncs) and the edge (on T, admin on T or an invite, grants) as they are. Tie them.
- **Tie bit**: an edge in `/members` gets a field `tied: bool` (also carried by roster snapshots). A tied edge's member is a group that lists the target; the edge exists because of that placement.
- **Add** is one commit: the placement of T into G (or of group U as G's subgroup) and the tied edge (G, T, role) with G's boxes in T's `/secrets`. Authority as today: write on G for the placement; admin on T, or an effective invite on T of at least `role`, for the edge. Without edge authority the write is a plain placement and T is excluded (members of G see the tid, not T). "Only what you may share" stays.
- **Remove** is `unplace`, synchronous, and the tied edge's removal is a **core obligation**, as link finalization is (spec/permissions.md §9): a node that holds a tied edge (G, T) and whose applied state has no placement of T in G MUST remove the edge when it may, after a complete pass of T's labels (spec/permissions.md §3): as an explicit demotion when it has admin on T (frontier, rotation of T in the same commit, pre-sync by the stored policy, §5.3), else as a self-removal when it has admin on G (no frontier, no rotation; T's next writer or admin rotates, §3). The node that unplaces does both in one commit when it may do so without a pre-sync (a self-removal), else it unplaces and the obligation follows. Nothing is queued by the app.
- **One direction only.** Placement gone, edge goes. Edge gone while the placement stays (revoked by T's admin, or never granted) re-grants nothing: a stale placement must never undo a revocation. Re-sharing is placing again with a role (on an existing placement, only the edge is written).
- **Provenance** is the bit. An untied edge for G (a hand share with the group's actor) survives an unplace; a tied one goes. A hand grant to G on a T already placed in G stays untied.
- **States of T in G**, all honest and all shown by `reach`: placed and shared (tied edge); placed and excluded (no edge: the placer could not share, or T's admin revoked); unplaced with a tied edge (transient, until the obligation runs); placed with an untied edge (hand share plus organization).
- **Window after unplace**: T leaves G's closure, so no new blob of T goes under G's label (spec/sync.md §3 entitlement is by group); G's role holders keep T's secrets until the lazy rotation, as any removal (spec/requirements.md: removal never re-encrypts). Nothing new leaks.
- **Nesting**: `add_subgroup(G, U)` with a role ties (G, U); items placed into U later get tied (U, item) edges by U's writers who may share them. Chains, cycles, the leave-out rule, costs: unchanged (notes/permissions.md Keys).
- **Concurrent add and remove offline**: a grant is remove + put of the member's entry (spec/permissions.md §2), so a concurrent re-add's edge survives a removal that never held it; the set add of the placement likewise. Whatever the join yields, the obligation rule restores consistency in the one direction that is safe. A tied edge whose placement a node never held counts as unplaced only once the node holds G's `/group` state (it must read G to judge; a node that does not sync G holds no obligation).
- **Timeline**: unchanged. Edge writes are judged as today; the tie bit changes nothing in §5.1 and is not an authority. The `/group` delta in the add commit is a content write on G, judged as today (write on G).
- **Keys**: unchanged. The tied edge's boxes are the grant's boxes; the departure on unplace is an ordinary departure of G from T.

## Spec edits (if adopted)
- spec/data-model.md §9: `tied: bool` in the `/members` value struct.
- spec/commits.md §2: a membership commit carrying a grant MAY also carry the one `/group` delta that places the grantee's target into the grantee (the tie); a self-removal MAY carry the one `/group` delta that unplaces it. Still one edge per commit.
- spec/permissions.md §2: the tie, its authority, and the obligation rule (next to §9's finalization MUST, same shape: who, when, after what pass).
- spec/permissions.md §1 and spec/requirements.md Permissions: "Grouping for sync grants no rights" stays true (the grant is the edge); add one sentence that a placement may be written together with a tied grant.
- notes/tags.md Sharing: replace "place plus grant" with the tied operation; notes/api.md the calls below.

## API
- `w.place(T, G)` / `w.add_subgroup(G, U)` unchanged (organize and sync, never share). Add `w.share_into(T, G, role)` (name open) writing placement plus tied edge in one batch; `Permission` when the node may not grant, with an opt-out that places anyway. Not a convenience wrapper: two calls cannot produce a tied pair in one commit.
- `w.unplace` / `remove_subgroup` unchanged in signature; they remove the tied edge in the same commit when that is a self-removal this node may make, and leave the obligation to run otherwise.
- `db.remove_edge_of(G, target)`: the missing self-removal by G's admin (fixes pain point 3 independently of the rest).
- `reach(T)` reports tied, untied and excluded per group so the app's confirmation and "who can see this" are right.

## Open decisions (owner)
1. Adopt tied grants over "placement grants access" (the invariant above is the argument).
2. Explicit sharing on place (`share_into` with a role; plain `place` never shares) versus implicit (placing into a group with non-owner role holders ties a grant at the placer's maximum). Recommended: explicit; the confirmation guideline (notes/tags.md) then has a clear trigger and nothing shares by surprise.
3. The owner rule "no helper; place plus grant is the operation" is withdrawn for this one operation.
4. Eventual edge removal after unplace (the obligation) is accepted, as link finalization is.
5. A removal by T's admin drops edits by G's holders on T that the admin had not received (the frontier rule, spec/requirements.md Permissions). For "remove from a shared tag" that is centralized semantics with the remover as the server. Yes or no.


Owner decision (round 13): all five open decisions as recommended (tied grants; explicit `share_into`; the "no helper" rule withdrawn for this operation; eventual tied-edge removal after unplace accepted; a removal by T's admin drops G holders' edits it had not received, softened later by receipts-only sync, issues/revoke-needs-whole-tree.md). Ready to implement.
