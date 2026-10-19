# Chat
> Summary: The group-chat pattern (entitlement, per-thing roles, writer stamps, inbox blobs) as built in examples/chat: chat actor, personas, join by link, removal through the link actor with rotation, disappearing messages with expiring placements, hide set, reactions, read marker, typing signals; what each step costs (estimates and measurements) and the limits the owner should know. Not reviewed by the owner.

## Structure (built: examples/chat, tests in examples/chat/tests/e2e.rs)
- **Chat actor C**: a group owned by the creator's person (better: a root actor, notes/permissions.md Patterns), synced on the creator's servers; C's label is the chat's label. Moderators are C's admins. C holds the title and the hidden-message set.
- **Every participant is a writer of C** (spec/requirements.md, Permissions): a reader could neither stamp its own messages (they would sit as deposits) nor add itself to C's `/group`. Viewers that never post can be readers.
- **Persona P_i** per participant per chat: a group owned by the participant's person, placed in C's items (for its own writes: `/created`, `/group`, secrets; a subgroup alone is not a member, spec/data-model.md §8) and C's subgroups (for its messages). `grant(P_i, C, read)` (written by P_i's owner) lets C's actor read what P_i owns and gives P_i secrets of its own; P_i needs no label: its commits live under C's label. It owns the participant's messages (placed in P_i), reactions and read marker, and its nick.
- **Messages**: things owned by P_i, created `Unsynced` with text and a sender-written `sent` time; the placement is a path op on P_i's `/group` in the same commit. One commit each.
- **Reactions**: `map<message tid, set<string>>` on P_j (the first reaction to a message `put`s the set: a path op into an absent key fails, issues/api-app-frictions.md). **Read marker**: a `tid` register on P_j. **Typing**: a `bool` signal on P_j (a listener per persona). **Hide**: an admin-written `set<tid>` on C; the timeline skips it; nobody edits or purges another owner's message.
- **Disappearing messages**: `expires_in` on the message's aspects and on its placement (a raw `/group` path op); gone on every node, offline ones too, at expiry.
- **Join by link**: K (a write link to C); the redeemer joins K by an invite grant, then makes its persona. A single-use link refuses a second redeemer.
- **Removal**: the moderator removes P_i from C's subgroups and items, then demotes the person where its edge is: on C for a direct grant, on K for a link joiner (`demote(C, person)` fails there: no edge on C), and revokes a multi-use K (the joiner may keep the seed, spec/permissions.md §9; the other joiners stay members of K). K's rotation cuts the joiner off C's new content; what P_i posts afterwards reaches nobody (P_i is outside C's closure). The node does not delete P_i's old entries with C's delete key; other members just stop listing them.
- **Timeline**: no query API yet: C's `/group.subgroups`, each persona's `/group.items`, each message, sorted by (`sent`, tid).
- **Not built**: time-bucket history groups (a label has no partial download, so one group per time bucket owned by C would let a new device fetch recent months first); deleting a removed persona's entries.

## Costs
- Old estimates: ~~join four commits and three boxes (~10–20 KB); message ≈ 350 B + content; removal 2 sealed boxes per remaining member (2 × 199 ≈ 480 KB at 200)~~.
- Design cost (spec as written, engine waste removed; issues/chat-costs.md has the breakdown):
  - **Join ≈ 38 KB.** Chain certificates under K's and C's labels (≈ 12 KB each, mostly hybrid KEM keys of 1216 B per role in `/keys`), the grant and the persona's own secrets (≈ 7.5 KB), the persona content commit (3 projections, 2 KB), two inbox blobs (4.5 KB).
  - **Message ≈ 2.1 KB of blobs (2.5 KB on the wire).** One commit makes 3 projections (`/created`, text + sent, the placement on the persona's `/group`), and each repeats the 467 B header and the signature.
  - **Removal of a link joiner.** Each K rotation costs 2.7 KB per remaining member (a read and a write sealed box) plus ≈ 5 KB fixed (`/keys` 2.6 KB, link-key and history boxes). C's rotation is ≈ 4 KB. `demote` plus `revoke_link` rotates both K and C twice, and K and C sit in the creator's home group, so the rotations go under the home label too. That is ≈ 79 KB at 4 members and ≈ 2.2 MB at 200. One rotation without the home copy is ≈ 45 KB at 4 and ≈ 0.55 MB at 200. Other members send only heartbeats.
- Measured today (chat of 4, `costs_join_message_removal`): join ≈ 220 KB, message ≈ 2.5 KB, removal ≈ 300 KB from the moderator plus ≈ 160 KB from the others. The excess is engine waste: issues/sync-upload-resend.md and issues/labeling-cert-copies.md.
- Cheaper by spec or app choices (issues/chat-costs.md, knobs): one rotation per link-joiner removal, chats not placed in the home group, one sealed box per member for all roles, one KEM key per keyset, the header once per commit, certificate dedup across nodes.
- Vandalism: any participant can edit C's `/group` and `writer`-purgeable bodies of C's own aspects; honest clients re-add their own persona deterministically and admins remove the vandal (authenticated malicious writers are bounded, not prevented).

## Open
- Whether participants writing C's `/group` is acceptable, or C's `/group` should list personas by an admin-only flow.
- Wake priority per chat is undecided (notes/networking.md, Priority); timeline query shape (notes/api.md).
- A second link made after joins plus a removal settles (`second_link_then_removal`); the later link's joiner used to rotate C without end (notes/node.md).
