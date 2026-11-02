# Chat design E: the chat's history is the chat
> Summary: A chat C is one ownerless thing, actor and label; members hold write on C and every message is one write on a message aspect of C, kept as history by retention `author` with keep at least forever (a permanent delta); the sender is the header's actor checked by a display rule until core verifies it, admins and the sender may purge, nobody else may drop or hide a body. No member actor, no member list, no per-message thing. Moderator delete, lasting tombstones and cheap kicks fall out of existing rules once the frontier study lands; new: a history read API, partial fetch, a history-less grant. Citations: `e-evidence.md`; corrections from `e-review.md` applied.

**A chat is a faction** (notes/chat-designs/e-factions.md): an actor with members and a message aspect; servers, teams, channels and roles are the same thing, nested by grants. Nothing below changes for a plain chat.

**[unbuilt]** marks a claim resting on core work not yet built: ownerless things, the frontier study (notes/frontier-study.md), the history read API, partial fetch, the history-less grant, purge modes, keep-after-removal, the verified actor.

**Verdict: E2 over E1.** E1 (a register holding the tid of the last message thing) does not put the message in C's closure (closure runs only through member lists, spec/data-model.md §8), so each message would again need a member actor and a placement. E2 (the message *is* the write) needs neither. The crux, whether another member can destroy or hide a superseded body, holds at honest nodes: with keep at least forever a body is must-hold for good, compaction may not drop it, only purge rights decide, and a non-admin holds no delete key for it (e-review §1).

## What is different

There is nothing but C: an ownerless actor **[unbuilt]** synced as a group of itself with an empty member list; its label carries its own aspects, members are its roster. A message is a delta on `chat:msgs:y2026.0` (one aspect name per year; that bounds only re-merge); author, time and retention come from the signed header. The register's value is unused; the held bodies are the chat. A required retention on the chat **[unbuilt]** refuses deltas with any other.

## Permissions and topology

| thing | owner | roles on it | written by |
|---|---|---|---|
| C: actor, group of itself, label; `chat:msgs:y2026.0` (one write per message; retention `author`, keep at least forever), `chat:reactions.0` (same), `chat:settings.0^`, `chat:hidden.0^`, `chat:next.0^`, read marker and typing (memory) | none (ownerless) | members: write; admins: admin | members; `^` aspects by admins |

**Who sent this.** The header's `actor` is checked by validity: a commit is invalid unless its signing device holds write on that actor at the commit's key (spec/permissions.md §5.2, Acting), so a valid commit's actor is its sender. Nobody can speak as another, and a "Bob deleted" marker from someone else's device is hidden.

## Common operations

- **Send.** One commit, one delta, about 0.5 KB; one message per commit. Order by commit time; each device knows when it received it.
- **Read.** History, not state: held bodies with author, time, validity and the sender flag, paged by time, memory commits included **[unbuilt]**. Reactions and read markers likewise. Partial and newest-first fetch for a new device **[unbuilt]**; today a new device replays the whole label.
- **Edit.** Not osis editing: a new message with `replaces` naming the commit ID of the original, honored only if both have the same verified sender; newest by (time, commit ID) wins, in any arrival order. Replies and reactions keep naming the original. Modes: old text purged; old text kept as visible edit history; editing off (ignore `replaces`). Owner notes this is the one place E does not use normal osis editing.
- **Delete for everyone.** A purge request: one body dropped everywhere honest, deleted at hosts with the sender's account key. The header-only blob is the lasting tombstone: a purged permanent delta's header is never dropped and stays must-hold, so new devices get it too **[unbuilt]**.
- **Moderator delete.** An admin purges the delta. Purge modes unnested **[unbuilt]**: author-only (admins cannot delete) is a chat setting; `admin` is admin-only delete; `nobody` is a permanent chat. A purge item by (aspect, author) **[unbuilt]** erases a removed member's flood in one item, within each write's own purge rights: it never overrides author-only or `nobody` (owner), so under those settings a flood stays. That is the setting's point, and it is not the default.
- **Disappearing.** `expires` on the delta; hosts delete unattended. Expiring deltas are not permanent and take the ordinary frontier path.
- **Kick.** One commit: removal and C's rotation (2.7 KB per remaining member). With the frontier study **[unbuilt]** the frontier names one head per message aspect and device, so a kick costs the same at 10 messages and 10 million, no snapshot can hide the kicked member's past, and a device removal is one head per aspect it wrote. Posts the kicker had not received still drop for everyone (`WaitForSync::Required` narrows this to the 30 s before the stamp); later or backdated posts are invalid wherever the kick is held; re-adding revives them. A modified kicked client gets nothing through. What the kicked device keeps is a property of the removal or the actor **[unbuilt]**; the chat default is the owner's to confirm.
- **Leave.** Self-removal; an admin follows with an explicit removal, so backdated posts are audited.
- **Hostile member.** Can only add. Junk written under `nobody` is hidden but cannot be erased, since nothing overrides that retention; a required retention on the chat **[unbuilt]** (issues/required-retention.md) makes it invalid and droppable. Wrap poisoning at hosts is a general osis hole (issue filed).
- **Hosts, block, links, strangers.** As C. An ownerless C needs a host that admits its label explicitly.

## Adding without history

Primary: a core **history-less grant** (issues/history-less-grant.md) **[unbuilt]**: a read rotation at the add with earlier secrets sealed per prior holder instead of a shared history box, a newcomer node that tolerates entries it cannot open, every author's chain certificates re-placed under the new epoch (about 11.5 KB per member). The newcomer never held an earlier box, so review4's flaw does not apply. Documents and folders want the same.

Fallback, no core change: **segments**. The app's chat is a chain of osis chats; an admin creates C2, grants every current member and the newcomer, copies the settings, and adds C2 to C1's `chat:next.0^` (admin-only set). Old members stitch by time; the newcomer holds only C2 and learns nothing of C1. Rules: on seeing `next`, any admin re-applies roster changes across segments; links made on C1 die at each segment; a kick is one commit per segment; a late post to C1 stays there; `next` is a set, so a fork shows both branches to old members and one to each newcomer. About 15 KB per member per segment.

## Core changes needed

- **History read API** (bodies with author, time, received time, validity, sender flag; memory commits; a change event per commit). Without it there is no chat.
- **Frontier study** (heads for permanent deltas). Without it a kick costs 34 B per message ever sent, caps near 2.5×10^5 messages, and any snapshot hides a kicked member's past.
- **Ownerless things**, **purge by author**, **unnested purge modes**, **partial fetch**, **history-less grant**, **keep-after-removal**, **verified actor** (or the display rule). As before: sender card, wake relay. Not needed: add-only member list, entry API, delegated purge, a burned-owner helper.

## Costs

Message about 0.5 KB on the wire, about 1.2 KB stored at every device for good; join about 35 KB; kick 2.7 KB per remaining member plus a few 60 B heads. Expired or purged: about 33 B residue, 300 B for a purged permanent delta's tombstone. Open is O(all commits): about 6 s at 10^6 messages, first sync about 15 min (extrapolated, e-review §6); re-adding a member rebuilds the year's aspect, about 70 s at 10^6. A hostile 10^7-message flood costs every member about 5 GB until purged by author.

## Rules leaned on

Retention bounds and purge rights per edit are promised (requirements Deletion); a history read API is not. A writer's snapshot may misstate others' content in state; history reads bodies, so the chat is immune. Member forward secrecy is parked (design D, refuted by review4).

## Core work this depends on

Ownership: issues/ownerless-things.md. Kick cost and history: issues/frontier-clobbers-history.md (study by the other coordinator). Reading: history-read-api, partial-history-fetch. Rights: purge-rights-not-nested, purge-by-author, required-retention. Tombstones: purge-tombstone-forever. Removal: keep-after-removal. Adding: history-less-grant. Hostile: writer rotating to itself (recovered by `repudiate`, spec/permissions.md §3), fresh-deposit-seed-readable-by-departed, wrap-poisoning-hides-from-new-devices. Costs at 10^6 commits per aspect are unmeasured (issues/node-core-gaps.md). Needed only for large factions, target 10,000 members (owner; comfortable at about 1,000 to a few thousand with the issues above fixed, 100,000 not designed for): default-off sync of children, a settle rule for cascade rotations (no forks), pure readers placing no chains, cards or heartbeats under big labels, frontier heads by commit ID.

## Accepted by the owner

A stolen unlocked device shows history; no deniability; deletion binds only honest clients; hosts see metadata. Eventual revocation is a general osis limit, not chat's.

## Sorting into the owner's categories

- **Default:** moderator delete; lasting tombstones; others keep a kicked member's messages; block local; disappearing timer per chat; add with history; edits purge the old text.
- **Setting:** add without history; permanent chat (`nobody`); admin-only or author-only delete; edit history kept or editing off; private read position; members may invite; a removed member erases its copy (owner: the default is keep).
- **Not exposed, clean for another app:** channels; per-year things owned by C with their own labels.
- **Incompatible:** a newcomer in a fork seeing the other branch; keeping a pre-kick message the kicker never received; readers reacting in a channel.
