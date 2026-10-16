# Self-join with a bounded role, and self-removal
> Summary: A share link should let a holder add itself with a role and nothing else; today link holders are admins of K and can remove other joiners. Members should also always be able to leave. Proposal: an invite power on edges plus an explicit self-removal rule; needs an owner call and a fixpoint model update.
> Tags: permissions, security, owner-call

## Problem
Links (spec/permissions.md §9) make L an admin of K, so every link holder sees who joined, can remove other joiners and holds K's label hard-delete key (notes/permissions.md, Links caveats). What a share link should convey is the capability to add oneself to a target with a bounded role, nothing more. The chat deep dive needs the same thing: a joiner must be able to add itself without any admin online, and must not be able to remove others.

Self-removal: spec/permissions.md §2 says membership writes are by admins, while §5.1 says a self-removal audits nothing (implying it applies). Make it explicit that a member may always remove or lower its own edge, whatever its role.

## Proposal
- Edge value gains an optional `invite: role` (max role the member may grant). Timeline rule (§5.1 step 2): a grant also applies if its author holds `invite ≥ granted role` on the target at that point and the write only adds an edge for an actor not currently in the roster (no change, no removal). Inviters hold the role secrets they seal (their own role and below), so the grant can carry boxes as today. When an inviter is demoted, its grants are audited by the demoter's frontier like any membership write, so nothing new is needed there.
- Self-removal: a write by X lowering or removing X's own edge always applies and audits nothing (as §5.1 already says for the audit).
- Links then become: L's edge on K = (role r, invite r), and the sharer stays K's only admin. Everything else about links (K's label, `until`, single use, finalization, bearer use) is unchanged. K can be dropped entirely (L directly on the target) when grouping joiners is not wanted.
- `tools/fixpoint`: model invite grants and non-admin self-removal (add to issues/fixpoint-coverage-gaps.md when adopted).

## What it does not solve
Grouping is content, not membership: a chat joiner must also put its participant actor into the chat's `/group`, a content write on a chat-owned thing. Only a write role allows that, and writers can also remove others (a reset; honest clients re-add). The chat pattern needs a chat-owned roster group with a write edge for participants (or for K), accepting that vandalism window, or the owner may want an add-only content op, which does not exist and would be new machinery.
