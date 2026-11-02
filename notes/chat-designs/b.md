# Chat design B: messages as things in the chat's list
> Summary: The second draft, corrected. As A, but every message is added to C's own member list, so a kicked member's placements are judged by the kick's frontier and its later posts are unlisted everywhere. Costs: the one-commit send leaves a rejected or removed message's body at hosts (only unlisted), pre-kick messages the kicker had not received vanish for everyone and come back on re-add, any member can unlist any message, and every message is a thing. Kept for comparison; C supersedes it.

## What is different

Adding a message is a write on C's list, which needs write on C at that moment. Osis's revocation rule then rejects a kicked member's later placements with no client rule. The member actor M is an item of C only.

## Permissions and topology

| thing | owner | roles on it | written by |
|---|---|---|---|
| C: actor, group, label; `chat:settings.0^`, `chat:hidden.0^`; its list holds each M and every message | burned key | members: write; admins: admin | members add their own M and messages; admins |
| M: actor; nick, reactions, read marker, typing | the member's account | C: read, not tied | the member's devices |
| message: `chat:msg.0`, in C's list | M | none | the sender's devices |

## Common operations

- **Send.** One commit: create the message under M, write it, add it to C's list. Because the commit touches C, its body is in C's required set whatever happens to the placement: unlisting or rejecting a message does not take its text off hosts.
- **Kick.** As A. The member's later placements are rejected wherever the kick is held, so a slipped post appears and then vanishes. Pre-kick placements the kicker had not received are dropped for everyone; the pre-sync narrows this. Re-adding the member revives every placement it made meanwhile. Edits of old messages are not placements and behave as in A.
- **Moderation.** Unlist plus hide; the body stays at hosts unless the sender purges or the member is wiped.
- **Member list.** Any member may unlist any message or any M, or reset the list in one write; kicking the vandal does not undo it.
- **Who sent this.** As A, plus "has a valid text", since anyone can create an empty thing owned by another's M and list it.
- **Paging.** Chat-owned per-year sub-groups, each with its own label, let a new device fetch recent history first.

## Core changes needed

As A.

## Sorting into the owner's categories

- **Default:** as A; unlisted messages hidden.
- **Setting:** as A.
- **Not exposed, clean for another app:** per-year labels for paging.
- **Incompatible:** keeping a pre-kick message the kicker never saw; removing a message's bytes from hosts by unlisting; stopping per-message list vandalism; per-message state under about 150 B per device.
