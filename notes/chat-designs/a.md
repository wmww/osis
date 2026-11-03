# Chat design A: messages as things in the member's group
> Summary: The first draft, corrected. A chat C is an actor, group and label owned by a thrown-away key; each member has a member actor M, added to C's member list, with C granted read on M (not tied); every message is a thing owned by M, added to M's own group. Sender-only edit and purge, but any member can edit C's member list, and a kicked member's writes stay valid, stopped only by the upload stamp. Kept for comparison; C supersedes it.

## What is different

Messages live in each member's own group, so adding a message never touches C. Rights are exactly as in C. The read grant is untied, since a tied grant let one vandal's list edit make every honest device erase a member's messages.

## Permissions and topology

| thing | owner | roles on it | written by |
|---|---|---|---|
| C: actor, group, label; `chat:settings.0^`, `chat:hidden.0^`; member list holds each M | burned key | members: write; admins: admin | members add their own M; admins |
| M: actor, group; nick, reactions, read marker, typing; its group lists the member's messages | the member's account | C: read, not tied | the member's devices |
| message: `chat:msg.0`, in M's group | M | none | the sender's devices |

## Common operations

- **Send.** One commit: create the message under M, write it, add it to M's group.
- **Kick.** Remove the account's write on C with C's rotation. The member's writes on M stay valid, so a modified client can still post or edit through a host the kicker has not updated or a relaying member; honest members then re-upload them. Pre-kick messages the kicker never received stay.
- **Moderation.** Hide by tid; wipe a member by removing C's read on M (hosts and honest devices drop everything of that member).
- **Member list.** Any member may remove another member's M or reset the list; hosts then delete that member's blobs, existing devices keep theirs, new devices get nothing, and anyone may add M back and re-upload. Kicking the vandal does not undo it.
- **Who sent this.** The account owning M, shown only if C is on M's roster and that account holds or ever held write on C.

## Core changes needed

Sender card in invite requests; keep-read-only policy on removal; wake relay (does not block). Nothing else.

## Sorting into Tess's categories

- **Default:** kicked member keeps own messages; others keep a kicked member's history; block is local.
- **Setting:** wipe a member on kick; show a deletion tombstone; private read position.
- **Not exposed, clean for another app:** permanent chats (retention `nobody`); channels.
- **Incompatible:** stopping list vandalism; stopping a kicked member's late writes by rule; per-message state under about 150 B per device.
