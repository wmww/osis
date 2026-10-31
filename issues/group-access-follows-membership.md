# Should a group's role holders get access to the group's members?
> Summary: today a thing's group membership (`/group`) organizes and syncs but grants nothing; sharing what is in a group is a second, separate step (a role grant per member thing), and apps cannot keep the two in step reliably. Proposal: group membership carries access (a group's role holders get their roles on its members), for every group. Owner call; design wanted.
> Tags: permissions, crypto, api, owner-call

Terms (owner decision, rename pending in issues/rename-roles-members.md): a **role** is the rights edge (actor, target, read/write/admin; today "membership", `/members`); a thing is a **member of a group** when the group's `/group` lists it (today "placement"). Whether a group is shown to users (a tag: a group with `/tag` metadata) is orthogonal to everything here.

## Current design (notes/tags.md "Sharing a tag", decided with the owner)
Sharing a group's contents: the group becomes an actor (secrets of its own, a label); each member thing gets a role grant for the group's actor; a member group gets one too, so access chains down; only things the sharer may grant on are shared. Adding a thing is "add to the group, then grant"; removing is "remove, then revoke". Owner, then: no core helper, "place plus grant is the operation".

## Why it fails in practice (the app prototype built it; its buggiest code, removed)
1. Two separate commits, synced separately: a device that sees the addition but not yet the grant and removes the thing leaves the grant behind (the thing stays shared after the user took it out); a grant can also arrive after a removal it never saw.
2. No provenance: a grant made by adding cannot be told from one made by hand, so removing may revoke a manual share.
3. Someone removing my thing from their group cannot revoke their group's grant on it (they are not admin of my thing): their group keeps access.
4. Revocation becomes app work: a durable queue, retries, deciding whether it is still needed (other paths, cycles).
Not a misunderstanding of the design: the two halves are not one unit, so no app can make them reliable.

## Proposal: membership carries access
A group's role holders get their roles (capped by the group's role) on every member thing, now and later; membership in a member group chains.
- No per-group switch: a private group (only its owner holds roles) gives nobody new access; sharing a group is granting a role on the group, as today.
- Adding a thing to a group shares it, so it needs authority to share that thing (at least admin, or an invite right). On the key side adding means sealing the thing's keys for the group, which only such a node can do. A thing added without that authority is a member (organizes, syncs for those who can already read it) but grants nothing; the honest "only what you may share" property of the current design stays.
- Removing a thing from a group is the revocation: one write, no provenance question (access through the group is exactly what membership gave), no separate grant to race.

## Alternative
Keep grants separate, add core operations that write the addition and its grant as one commit with provenance (the grant tied to the membership entry). Fixes 1, 2 and 4; 3 stays unless removal by the group's admin may also drop the tied grant. Two concepts still to keep in step.

## Questions for the design
- Key handling: per thing sealed to the group (as today's grants) vs the group's keys unlocking members'; rotation cost when a group's role holders change (today one lazy rotation per thing below, owner-accepted for thousands of things).
- Removal semantics: who may remove a thing from a group (the group's writers? the thing's admins?), and what a removal by a non-admin of the thing revokes.
- Nesting and cycles (groups are a graph): reach, cost, and the leave-out rule (round 13 item 129).
- Interaction with the validity timeline (membership changes become rights changes: audit, frontiers, backdating), and with offline concurrent add/remove.
- What remains of explicit per-thing role grants (still needed for sharing one thing with one person).
