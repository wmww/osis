# Chat
> Summary: The group-chat pattern (entitlement, per-thing roles, writer stamps, inbox blobs) as built in examples/chat: chat actor, personas, join by link, removal through the link actor with rotation, disappearing messages with expiring placements, hide set, reactions, read marker, typing signals; what each step costs (estimates and measurements) and the limits the owner should know. Not reviewed by the owner.

## Structure (built: examples/chat, tests in examples/chat/tests/e2e.rs)
- **Chat actor C**: a group owned by the creator's person (better: a root actor, notes/permissions.md Patterns), synced on the creator's servers; C's label is the chat's label. Moderators are C's admins. C holds the title and the hidden-message set.
- **Every participant is a writer of C** (spec/requirements.md, Permissions): a reader could neither stamp its own messages (they would sit as deposits) nor add itself to C's `/group`. Viewers that never post can be readers.
- **Persona P_i** per participant per chat: a group owned by the participant's person, placed in C's items and C's subgroups. `grant(P_i, C, read)` (written by P_i's owner) lets C's actor read what P_i owns and gives P_i secrets of its own; P_i needs no label: its commits live under C's label. It owns the participant's messages (placed in P_i), reactions and read marker, and its nick.
- **Messages**: things owned by P_i, created `Unsynced` with text and a sender-written `sent` time; the placement is a path op on P_i's `/group` in the same commit. One commit each.
- **Reactions**: `map<message tid, set<string>>` on P_j (the first reaction to a message `put`s the set: a path op into an absent key fails, issues/api-app-frictions.md). **Read marker**: a `tid` register on P_j. **Typing**: a `bool` signal on P_j (a listener per persona). **Hide**: an admin-written `set<tid>` on C; the timeline skips it; nobody edits or purges another owner's message.
- **Disappearing messages**: `expires_in` on the message's aspects and on its placement (a raw `/group` path op); gone on every node, offline ones too, at expiry.
- **Join by link**: K (a write link to C); the redeemer joins K by an invite grant, then makes its persona. A single-use link refuses a second redeemer.
- **Removal**: the moderator removes P_i from C's subgroups and items, then demotes the person where its edge is: on C for a direct grant, on K for a link joiner (`demote(C, person)` fails there: no edge on C), and revokes a multi-use K (the joiner may keep the seed, spec/permissions.md §9; the other joiners stay members of K). K's rotation cuts the joiner off C's new content; what P_i posts afterwards reaches nobody (P_i is outside C's closure). The node does not delete P_i's old entries with C's delete key; other members just stop listing them.
- **Timeline**: no query API yet: C's `/group.subgroups`, each persona's `/group.items`, each message, sorted by (`sent`, tid).
- **Not built**: time-bucket history groups (a label has no partial download, so one group per time bucket owned by C would let a new device fetch recent months first); deleting a removed persona's entries.

## Costs
- Estimates: join = persona creation, two membership commits and one content commit, two sealed boxes (C's read and write secrets to the person) plus one box (C's read secret to P_i). Message ≈ 350 B plus content. Removal from a 200-person chat: 2 × 199 sealed boxes ≈ 480 KB in one paged commit, downloaded by every participant; sub-actors of about 50 (channels as actors under C) keep a removal near 120 KB.
- Measured (chat of 4, upstream bytes at the server, `costs_join_message_removal`, tier 2): join ≈ 220 KB, message ≈ 2.5 KB, removal of a link joiner ≈ 350 KB from the moderator plus ≈ 160 KB from the others. Far over the estimates: issues/chat-costs.md, issues/sync-deposit-resend.md.
- Vandalism: any participant can edit C's `/group` and `writer`-purgeable bodies of C's own aspects; honest clients re-add their own persona deterministically and admins remove the vandal (authenticated malicious writers are bounded, not prevented).

## Open
- Whether participants writing C's `/group` is acceptable, or C's `/group` should list personas by an admin-only flow.
- Wake priority per chat is undecided (notes/networking.md, Priority); timeline query shape (notes/api.md).
- A second link made after joins plus a removal never settled in the test world (issues/chat-costs.md).
