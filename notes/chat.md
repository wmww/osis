# Chat
> Summary: The group-chat pattern derived from the current design (entitlement, per-thing roles, writer stamps, inbox blobs), what each join, message and removal costs, and the limits the owner should know. Not reviewed by the owner.

## Structure
- **Chat actor C**, owned by the creator's person actor or, better, by a root actor (notes/permissions.md, Patterns). Moderators are C's admins. C's label (its home label) is the chat's label. C's data: title, hidden-message set, settings.
- **Every participant is a writer of C** (spec/requirements.md, Permissions): a reader could neither stamp its own messages (they would sit as deposits) nor add itself to `/group`. Viewers that never post can be readers.
- **Persona P_i** per participant per chat: an actor owned by the participant's person actor, with secrets of its own. It owns the participant's messages, reactions and read marker, and it is the group listing its messages. Edge (C, P_i, read) so C's actor reads everything P_i owns (entitlement under C's label); P_i added to C's `/group` items (its own writes: `/created`, `/group`, secrets; a subgroup alone is not a member, spec/data-model.md §8) and subgroups (its messages). P_i needs no label of its own: its commits live under C's label.
- **Messages**: plain things owned by P_i (derived secrets, no boxes), placed in P_i's `/group.items`. One commit each (content, `/created`, the placement), about 350 B plus content.
- **Reactions**: `map<message tid, set<string>>` on P_j (tombstones forever, cheap). **Read marker**: a register on P_j. **Typing and presence**: signals on P_j under C's label (a writer signs with C's write key; a reader may use the deposit key). **Disappearing messages**: `expires` on the message's deltas, placement included. **Hide**: an admin-written set on C; nobody edits or purges another owner's message. **Removal**: remove P_i's edge on C (its person's write edge too), rotate C's read and write, delete P_i's entries with C's delete key; other members drop them as outside the closure.
- **Join by link**: K with write on C; the joiner invite-grants its person into K, then creates P_i and writes the two P_i edges itself (P_i is its own; the (C, P_i, read) edge is P_i's admin's to write, and C's `/group` write is a writer's).
- **History**: a label has no partial download, so one group per time bucket (owned by C, derived keys, its own label) lets a new device fetch recent months first.

## Costs
- Join: persona creation plus two membership commits and one content commit; two sealed boxes (C's read and write secrets to the person) plus one box (C's read secret to P_i).
- Removal from a 200-person chat: 2 × 199 sealed boxes ≈ 480 KB in one paged commit, downloaded by every participant; a month-offline device walks the missed steps and downloads each rotation. Sub-actors of about 50 (channels as actors under C) keep a removal near 120 KB.
- Vandalism: any participant can edit C's `/group` and `writer`-purgeable bodies of C's own aspects; honest clients re-add their own persona deterministically and admins remove the vandal (authenticated malicious writers are bounded, not prevented).

## Open
- Whether participants writing C's `/group` is acceptable, or C's `/group` should list personas by an admin-only flow.
- Wake priority per chat is undecided (notes/networking.md, Priority); timeline query shape (notes/api.md).
