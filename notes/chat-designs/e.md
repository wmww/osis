# Chat design E: the chat's history is the chat
> Summary: A chat C is one thing, actor and label; members hold write on C and every message is one write on a message aspect of C, kept as history by retention `author` with keep at least forever; the sender is the signed header's actor, admins and the sender may purge, nobody else may drop or hide a body. No member actor, no member list, no per-message thing. Moderator delete, tombstones and kicks fall out of existing rules; new: a history read API, and "add without history" as a chain of chats. Citations: `e-evidence.md`.

**Status:** reviewed, corrections pending; e-review.md overrides this file where they differ (sender verification, frontier cost, snapshots, tombstones).

**Assumes (owner):** a kick does not clobber the kicked member's history; fixed in core regardless (issues/frontier-clobbers-history.md). Its size is still open.

**Verdict: E2 over E1.** E1 (a register holding the tid of the last message thing) does not put the message in C's closure (closure runs only through member lists, spec/data-model.md §8), so each message would again need a member actor and a placement: C's machinery plus a tid log. E2 (the message *is* the write) needs neither. The crux, whether another member can destroy or hide a superseded body, holds: with keep at least forever a body is must-hold for good, compaction may not drop it, only purge rights decide, and a non-admin holds no delete key for it.

## What is different

There is nothing but C: an actor synced as a group of itself with an empty member list; its label carries its own aspects, members are its roster. A message is a delta on `chat:msgs.0` (a new aspect name per year); author, time and retention come from the signed header. The register's value is unused; the held bodies are the chat. The app shows only deltas with the requested retention.

## Permissions and topology

| thing | owner | roles on it | written by |
|---|---|---|---|
| C: actor, group of itself, label; `chat:msgs:y2026.0` (one write per message; retention `author`, keep at least forever), `chat:reactions.0` (same), `chat:settings.0^`, `chat:hidden.0^`, `chat:next.0^`, read marker and typing (memory) | burned key | members: write; admins: admin | members; `^` aspects by admins |

Who sent this: a valid delta on the message aspect; its sender is the header's actor, tied to the signing device by validity. Nothing can be written as someone else: no fake members, no forged tombstones.

## Common operations

- **Send.** One commit, one delta, about 0.5 KB. Order by commit time; each device knows when it received it.
- **Read.** History, not state: held bodies with author, time and validity, paged by time. Reactions and read markers likewise, so nobody can fake another's.
- **Edit.** A new message referring to the old, plus a purge of the old.
- **Delete for everyone.** A purge request: one body dropped everywhere honest, deleted at hosts with the sender's account key. The header-only blob is the tombstone until headers are forgotten; a durable tombstone is a small marker write.
- **Moderator delete.** An admin purges the delta (`author` includes admins). No new feature; "admins cannot delete" is not expressible.
- **Disappearing.** `expires` on the delta; hosts delete unattended.
- **Kick.** One commit: removal and C's rotation (2.7 KB per remaining member). The frontier judges the member's deltas: posts the kicker had not received drop for everyone (the pre-sync narrows this), later or backdated posts are invalid wherever the kick is held, re-adding revives them. A modified kicked client gets nothing through. The kicked device drops the chat, its own messages included.
- **Leave.** Self-removal; an admin follows with an explicit removal, so backdated posts are audited.
- **Hostile member.** Can only add. Junk written with retention `nobody` is hidden but can never be erased.
- **Hosts, block, links, strangers.** As C.

## Adding without history (owner's idea, traced)

A chat in the app is a chain of **segments**, each an osis chat as above. To add someone without history, an admin creates C2, grants every current member and the newcomer, copies the settings, and adds C2 to C1's `chat:next.0^` (admin-only set). Old members stitch C1 and C2 by time; the newcomer holds only C2.
- **Newcomer learns:** nothing. C2 carries no pointer back; a tid is a bare reference and C1's label and hosts live under C1's label.
- **Who creates it:** anyone can make a new chat with the same people, but only an admin's `next` is stitched. A link joiner sees its segment from its start; a no-history joiner needs an admin online.
- **Cost:** per member one grant (about 2.7 KB) and its chain certificates under the new label (about 11.5 KB), one more label to sync; about 15 MB at 1000 members against 2.7 KB per member for a kick. Estimated.
- **Old segments** stay live: reactions, edits and purges there still work; an offline member's late post to C1 is re-posted to C2 by its app.
- **Kick** applies to every segment the member is in; current segment only is a setting that leaves it reading and writing the old one.
- **Fork:** two admins offline each make a segment with different newcomers; `next` is a set, old members stitch both, each newcomer sees only its branch; admins merge with a third segment. Deterministic.
- **A member left out** keeps C1 and sees the chat go quiet; a segment carries the whole roster.

**Alternative, a core history-less grant:** a read rotation at the add whose earlier secrets are sealed per prior holder instead of a shared history box, a newcomer node that tolerates entries it cannot open (a link-key bearer already does), and every author's chain certificates re-placed under the new epoch (about 11.5 KB per member, the same bill). It changes history boxes, re-seals, claims and established epochs (spec/crypto.md §4). The flaw that sank design D (review4: a seed box in the recording opens under keys the device keeps) does not apply: the newcomer never held an earlier box, and earlier secrets are sealed only to prior holders. Documents and folders cannot be segmented, so they would want it; a chat does not. **Recommend segments:** no core change, same cost, works for every topology.

## Core changes needed

- **History read API:** held bodies of an aspect with author, time, received time and validity, paged by time, plus a change event per commit. Without it there is no chat.
- **Purge of invalid bodies:** admins may purge the body of an invalid delta whatever its retention. Without it a kicked member's `nobody` junk is stored by everyone for good.
- As before: sender card, keep-read-only policy, wake relay. Not needed: add-only member list, entry API, delegated purge, history-less grant.

## Costs

Message about 0.5 KB; join about 35 KB; kick 2.7 KB per remaining member. Per device: the bodies, plus about 33 B per expired or purged message (12 MB for ten years at 100 a day). Open at a million messages: a kick re-reads the aspect's history to un-merge; one aspect name per year bounds it. Frontier: 10 B per aspect and device today, 32 B per message since the last snapshot after the session change; an occasional one-value snapshot (drops nothing) keeps it small.

## Rules leaned on

Retention bounds and purge rights per edit are promised (requirements Deletion); a history read API is not. A writer's snapshot may misstate others' content in state; history reads bodies, so the chat is immune. Member forward secrecy is parked (design D, refuted by review4).

## Sorting into the owner's categories

- **Default:** moderator delete; visible tombstones; others keep a kicked member's messages; block local; disappearing timer per chat; add with history.
- **Setting:** add without history (new segment); permanent chat (`nobody`); admin-only delete (`admin`); durable tombstone markers; private read position; members may invite; kick from the current segment only.
- **Not exposed, clean for another app:** channels; per-year things owned by C with their own labels for paging.
- **Incompatible:** a kicked or leaving member keeping its own messages without the keep policy; "admins cannot delete"; erasing a modified member's `nobody` junk without the new rule; keeping a pre-kick message the kicker never saw; a newcomer in a fork seeing the other branch.
