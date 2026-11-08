# Chat cases
> Summary: Informal chat behavior cases with what chat (design E, notes/chat.md) answers: forced yes or no, app's choice, or needs a core change; `want` values are guesses for Tess to correct. Answers come from reading spec and code, run where libs/chat/tests covers them. Check a new chat topology against these.

Cells: `yes`/`no` forced; `opt` app's clean choice; `opt*` a modified client defeats it; `core x` needs core change x (list at the end); `?` not traced; `!` marks a forced answer that differs from want. "Honest" means the party's client follows the rules; "modified" means it does not. Kick cost cells assume frontier heads (notes/frontier-study.md, unbuilt). Assumed fixed (issues/): writer rotating to itself (removing it recovers, notes/crypto.md Lockouts), header forgetting, rotation-name growth, the query API.

## Identity and authorship

| case | want | chat |
|---|---|---|
| Can a member edit another member's message? | no | no |
| Can a chat admin edit another member's message? | no | no |
| Can a chat admin hide a message from honest clients? | yes | opt |
| Can a chat admin erase one message from serving nodes and honest devices? | yes | opt³⁸ |
| Can an admin of a member's account (their other device) edit that member's messages? | yes | yes |
| Can an admin of a team that is a member edit a team member's messages? | no | no |
| Can a member make a message appear as written by Bob? | no | no |
| Can a member make messages appear from a fake account that was never a member? | no | no |
| Does such a fake account's content cost every member storage until an admin removes it? | no | yes! |
| Does every reader see the verified sender of each message? | yes | yes |
| Can a member prove to outsiders that you wrote a message? | accepted | yes |
| Can a member purge another member's message? | no | no |

## A kicked member (honest client unless stated)

| case | want | chat |
|---|---|---|
| Can they still read their own old messages? | yes | yes |
| Can they still read others' old messages? | opt | opt |
| Can they read new messages? | no | no |
| Can they post? | no | no |
| Modified client: can a post reach others through a serving node the kicker has not updated yet? | no | no |
| Modified client: can a current member relay their post so it shows as theirs? | no | no |
| Modified client: can they edit or delete old messages so others see it? | no | no |
| Do others still see their old messages by default? | yes | opt |
| Can the kicker wipe their whole history from serving nodes and honest devices? | yes | yes²⁶ |
| Does their modified client keep what it downloaded? | accepted | yes |
| A message they sent before the kick that the kicker had not received: does it stay for others? | yes | no! |
| Re-added later: do posts their modified client made while kicked appear? | no | yes! |
| Re-added later: can they read what was sent while they were out? | opt | core n |

## Leaving

| case | want | chat |
|---|---|---|
| After leaving, can you read your own old messages? | yes | yes |
| After leaving, can you read others' old messages? | opt | opt |
| Do others still see your messages after you leave? | yes | opt |
| Can you delete your messages for everyone before leaving? | yes | yes |
| Can you delete your messages for everyone after leaving? | no | no |
| Modified client: can a leaver backdate a post before its leave so it stays? | no | opt⁵ |
| Does leaving wipe the chat from your device? | opt | opt |

## The member list

| case | want | chat |
|---|---|---|
| Can a non-admin add a member? | opt | opt⁶ |
| Can a non-admin remove a member? | no | no |
| Can members see the member list? | yes | yes |
| Can members see each other's device lists? | accepted | yes |

## Adding

| case | want | chat |
|---|---|---|
| Does a new member see the history? | opt | opt³³ |
| Segments: can the new member's modified client learn anything about the earlier chat? | no | no³⁴ |
| Segments: two admins add different people at once; is the outcome deterministic with nothing lost for old members? | yes | yes³⁵ |
| Adding one member without history to a 1000-member group under 20 MB? | yes | yes³⁶ |
| Can strangers join by link with no admin online? | yes | yes |
| Does a link joiner keep access when the sharer is kicked? | yes | opt⁷ |
| Can an admin kick one link joiner without killing the link? | yes | opt⁷ |
| Does a stranger's invite show a verified sender before accepting? | yes | core e |
| Does a stranger's invite fetch anything before you accept? | no | no |

## Devices

| case | want | chat |
|---|---|---|
| Does a new device get the full history? | yes | yes |
| Does a kicked member's new device get that member's own messages? | yes | no! |
| Can a removed (lost) device read new messages? | no | no |
| Does removing a device wipe the chat from it (honest device)? | yes | yes |
| Two devices of one member post offline at once: do both messages appear? | yes | yes |

## Delete and disappear

| case | want | chat |
|---|---|---|
| Delete for everyone: erased on honest online devices? | yes | yes |
| Erased on offline devices when they return? | yes | yes |
| Erased at serving nodes? | yes | yes |
| Attachments erased too? | yes | yes |
| Edit: does the old text leave serving nodes promptly? | yes | yes²⁷ |
| Disappearing message gone everywhere at its time, serving nodes unattended? | yes | yes |
| Offline device past the time: gone when it wakes? | yes | yes |
| Does a hostile device keep a deleted message? | accepted | yes |
| Can the app make messages undeletable (permanent chat)? | opt | opt* |
| Timer changed mid-chat: do old messages keep their old timer? | yes | yes |
| Does a disappeared message leave a trace on each device? | no | yes¹¹ |
| Does a deleted message leave the fact and time visible to members? | accepted | yes |

## Deletion traces (after a permanent delete)

| case | want | chat |
|---|---|---|
| Does the app show a "message deleted" tombstone by default? | opt | opt |
| Can the app be set to show no trace at all? | opt | opt |
| Modified client: can it tell a message existed, who sent it and when, from what osis keeps? | accepted | yes²⁸ |
| Can a member forge a "Bob deleted a message" tombstone for a message Bob never sent? | no | no |
| Can members tell an expired message from a purged one? | opt | opt²⁰ |
| Can a serving node tell that a message was deleted? | accepted | yes |
| Can a serving node tell who sent the deleted message, or what it said? | no | no |
| Can a serving node tell an expired entry from a purged one? | accepted | yes |
| Can a serving node forge a deletion that members show as a tombstone? | no | no |

## Moderation and abuse

| case | want | chat |
|---|---|---|
| Modified member: can it write junk nobody can ever erase from serving nodes and honest devices? | no | no³¹ |
| Can admins wipe a member's whole history from serving nodes and devices? | yes | yes²⁶ |
| Can admins get one illegal message off serving nodes without wiping the member? | yes | opt³⁸ |
| Can you block someone without deleting anything on either side? | yes | opt |
| Is your evidence kept after blocking? | yes | opt |
| Can a blocked contact you share a group with add you to a chat? | no | opt¹² |
| Can a stranger holding your contact card fill your invite inbox? | no | yes¹³! |
| Do message requests show a verified sender? | yes | core e |

## Admins

| case | want | chat |
|---|---|---|
| No admin left: can members still post and leave? | yes | yes |
| No admin left: can anyone add or kick? | no | no |
| Last admin leaves: is someone promoted? | yes | opt |
| Two admins remove each other at once: one deterministic outcome? | yes | yes |
| Can a hostile sole admin wipe the chat for everyone? | accepted | yes |
| Can a writer lock everyone out by rotating keys to itself? | no | no |
| Can the creator leave or be demoted? | yes | yes |

## Serving nodes (questions about one that cannot read the chat)

| case | want | chat |
|---|---|---|
| Does a serving node that cannot read it learn who is in the chat or what is said? | no | no |
| Does a serving node learn message sizes, times and expiries? | accepted | yes |
| Only serving node lost: can members move to a new one? | yes | opt¹⁴ |
| Members on different serving nodes of the chat: do they converge? | yes | yes |
| Can a serving node colluding with a kicked member read new messages? | no | no |
| Can a colluding serving node deliver a kicked member's post? | no | no |
| Can a member's own node serve the chat? | yes | opt |

## Order and display

| case | want | chat |
|---|---|---|
| Modified client: can a sender backdate a message into history? | no | yes! |
| Honest sender with a wrong clock: shown at a sane position? | yes | yes |
| Reply to a deleted message: shown as a placeholder? | yes | opt |
| Can a new device page recent history without downloading all of it? | yes | core o |
| Can the app show the latest 50 messages with the osis API alone? | yes | yes |
| Read receipts: can a member keep their read position private? | yes | opt |
| Typing: reaches connected devices only, stored nowhere? | yes | yes |
| Is a sender woken by its own post? | no | no |
| Notifications while the app is closed? | yes | core h |

## Costs

| case | want | chat |
|---|---|---|
| Kick in a chat with a million messages under a minute of work on a phone? | yes | ?³² |
| Kick or lost device in a 1000-member group under 10 MB upload? | yes | yes⁴⁰ |
| Fresh device of a disappearing chat under 50 MB after 10 years at 100 a day? | yes | yes |
| Long-lived device of a permanent chat holds every message body? | yes | yes |
| Join under 100 KB? | yes | yes |
| A message under 3 KB on the wire? | yes | yes |
| New device of a 1000-member group under 100 MB before any message? | yes | yes |
| One edit after compaction under 1 MB of upload? | yes | yes |
| Compacting a member's history under 100 MB of memory on a phone? | yes | yes³⁰ |
| Is a send one commit? | yes | yes |

## Channels and 1:1

| case | want | chat |
|---|---|---|
| Channel: only admins post, members read? | yes | yes |
| Channel: can read-only members react? | opt | no! |
| 1:1: the other side kicks you; do you keep their messages (honest client)? | yes | yes |
| 1:1: can either side kick the other? | no | opt* |
| Two 1:1 chats with one person created at once: shown as one? | yes | opt |

## Forward secrecy (a recording of the serving nodes plus one device stolen today)

| case | want | chat |
|---|---|---|
| Can messages deleted or expired more than two hours ago be read? | no | yes! |
| Can messages deleted in the last two hours be read? | no | yes! |
| Can old messages the device no longer shows be read? | no | yes! |
| Stolen keys only: can messages sent after the theft be read? | no | yes! |
| Can a removed member read what it already copied? | accepted | yes |
| Does anyone gain deniability? | accepted | no |
| A device offline for a year: can it read everything still at the serving nodes on return? | yes | yes |
| Can a new member read history without an existing member re-publishing it? | opt | yes |
| Do serving nodes end up storing content nobody can read? | no | no |
| Is protection per message, at once, rather than after a window? | yes | no! core j |
| Can a chat have forward secrecy at all? | yes | core m |

## Realms (notes/realms.md: servers, teams and roles are realms; a channel is a chat a realm holds write on)

| case | want | chat |
|---|---|---|
| Does removing a member from the top realm remove them from every channel at once? | yes | yes |
| Does one commit protect all new content from the removed member (channels re-key on the next sync)? | yes | yes⁴¹ |
| Does cutting the removed member's upload and sync keys need an admin step per channel per serving node? | no | yes⁴¹! |
| Can the removed member keep uploading junk to a channel until an admin steps it there? | no | yes! |
| Removal under 10 MB upload at 1000 members and 100 channels? | yes | yes⁴² |
| Removal under 10 MB upload at 100,000 members (nested rosters) and 100 channels? | yes | yes⁴² |
| Does a member's lost device or leave cost the next poster the top realm's whole rotation? | no | yes! |
| Is demoting a mod as cheap as a kick? | yes | no!⁴³ |
| Does each member's device download every other member's chains, cards and heartbeats under the top realm's label? | no | yes⁴⁴! core r |
| Kick pre-sync across 100 channels under a minute? | yes | ? |
| Can a mod mute one member in one channel while they hold the top realm? | yes | opt*⁴⁵ |
| Can a mod ban one member from one channel while they hold the top realm? | yes | no! |
| Can a mod time out a member for an hour? | yes | opt*⁴⁵ |
| Can a mod delete messages in some channels and not others? | yes | yes |
| Can a mod delete messages without also being able to lock the channel or change its roster? | yes | opt⁴⁶ |
| Can role holders add and remove others of their role? | opt | yes⁴⁷ |
| Read-only announcement channel where members can react? | yes | opt⁴⁸ |
| Does a read-only channel with 20 or more reader devices fill its deposit budget until a mod syncs? | no | yes! |
| Can any member create a channel that appears in the directory? | opt | opt⁴⁹ |
| Does the sidebar show channel names without reading each channel? | yes | yes⁵⁰ |
| Can non-members see that a private channel exists? | no | opt⁵¹ |
| Can a member post as a realm (the role actor)? | no | opt³⁹ |
| Can a member choose which channels to sync, with none by default? | yes | core s |
| Unread counts for channels not synced? | yes | opt⁵² |
| Mentions in channels not synced? | yes | core h |
| Threads without a new chat per thread? | yes | yes⁵³ |
| A document anyone in the realm can edit, synced to every member? | yes | yes⁵⁴ |
| Can a member remove another member's document from the realm's auto-synced content? | no | no⁵⁴ |
| The same chat in two realms? | yes | yes |
| Move a chat between realms without copying it? | yes | yes |
| A realm inside a realm, members inherited? | yes | yes |
| Is the kick and role history an audit log members can read? | yes | yes⁵⁵ |
| Realm-wide read-only mode in one step? | yes | opt*⁵⁶ |
| Per-member rate limits? | yes | no! |
| A realm with no admin left: posting still works? | yes | yes |

## Core changes

- **e** Sender card in invite requests (Tess: yes).
- **h** Wake relay for background notifications (Tess: does not block).
- **j** Per-sender key chains (Signal sender keys): per-message erasure, at the cost of a per-sender state per device and either a per-sender marker hosts can link or trial decryption.
- **m** Erasable per-device KEM keys with per-device boxes (MLS-sized): what real member forward secrecy would need; against spec/crypto.md §3 and requirements line 48.
- **n** History-less grant: a read rotation at the add with earlier secrets sealed per prior holder, no shared history box, chain certificates re-placed (issues/history-less-grant.md); segments (footnote 33) are the fallback without core change.
- **o** Newest-first fetch of a label: built (spec/sync.md §6); a device that stops fetching: issues/partial-history-fetch.md.
- **r** Pure readers place nothing under big labels: no chain certificates, node card or heartbeats from a reader unless asked (realms past a few thousand members).
- **s** Default-off sync: a device holding a realm's secret does not sync the labels of the things the realm holds until the app chooses (today `compute_labels` syncs every label whose secret the node holds).

## Footnotes

5. Once an admin writes an explicit removal of the absent grant, the leave is audited and the post is unlisted.
6. An admin gives member grants a `may_grant` level; then members may invite.
7. Only if the sharer's node granted the joiner directly on join (links are admin-only).
11. About 33 B of value-less residue per message.
12. The grant applies (sender is "connected"); the app leaves automatically.
13. Needs your contact card's keys; the remedy is a new card.
14. Needs two serving nodes listed, or direct member-to-member contact, for the replacement to be learned.
20. From held headers: an expired delta carries `expires`, a purged one is named by a purge request; after header forgetting both are residue.
26. for messages written with the requested retention; a modified sender's `nobody` message is hidden and stored for good, unless a required retention refuses it.
27. an edit is a new message plus a purge of the old one.
28. the header-only blob of a purged permanent delta is kept forever and reaches new devices, with its purge commit (spec/commits.md §5).
30. nothing is compacted; messages keep at least forever.
31. a required retention on every aspect makes `nobody` junk invalid, dropped without a right (spec/permissions.md §6); junk under the required retention is what purge by author erases; a member from before a change can still backdate below it.
33. Segments: the admin creates a new chat, grants everyone plus the newcomer, and the old chat points to it (admin-only); old members' apps stitch the two. No core change; Tess's primary path is core n (notes/chat.md Left out).
34. The new chat carries no pointer back; a tid is a bare reference and the old chat's label and serving nodes live under its own label.
35. The pointer is a set, so old members stitch every branch; each newcomer sees only its branch; admins merge with a further segment.
36. About 15 KB per member (grant boxes plus chain certificates under the new label): about 15 MB at 1000, estimated.
38. default yes; author-only purge (admins cannot delete) is a chat setting (core q, built).
39. the header's actor is checked by validity (spec/permissions.md §5.2: the signing device holds write on the actor at the commit's key), so a valid commit's actor is its sender; that the actor itself could write on the chat is the ordinary validity of the device's write only when its path runs through the actor.
40. with the frontier study; today a kick lists about 34 B per message the member ever sent (3.4 MB at 10^5) and caps near 1.9x10^6 messages.
41. The removal and the top realm's rotation are one commit (2.7 KB per member); each child re-keys on any writer's next sync pass (about 11 KB, eager, may fork). Cutting sync, write and deposit keys needs an admin of each child to register a step at each serving node; until then the removed member reads ciphertext and can upload.
42. At 1000: 2.7 MB plus about 11 KB per child, spread over members' passes. At 100,000 with tiers of 1000: the tier (2.7 MB), the top realm (100 boxes), then children; estimated.
43. All three roles rotate on every realm and chat the mod administered, admins only; the ex-mod keeps delete keys until each label is stepped.
44. Every syncing node places its chain (11.5 KB per account), card (1.5 KB) and four heartbeats a day under each label it reads: about 13 MB once and 2.4 MB a day at 1000; about 1.4 GB and 240 MB a day at 100,000.
45. By rights no: a role is the maximum over paths and `until` only ends a grant. Mods write a muted set with a time; honest clients hide and mods purge; a modified client posts on.
46. Messages on a thing under the chat with an admin grant for the delete role (spec/permissions.md §1): purge without roster or lock; one more rotation per kick.
47. Admin passes only through admin, and admins of a realm manage its roster; direct per-channel admin grants avoid it at one grant per channel.
48. A sibling chat the members write carries the reactions; the app shows them under the announcement.
49. Adding a channel is a grant for the realm on the chat, needing admin on the chat and on the realm's layout; a member creates a chat and asks an admin to add it.
50. The realm's grants are its contents (every member holds them through the realm's inbox copies); names and categories are a chat-app layout aspect on the realm. Channels are not in the realm's group, so nothing of theirs is under its label.
51. Grant the private channel only to a role realm. Left: its serving nodes see its label, a device-removal frontier head names its tid under public labels (frontier-study format), and a purge across children shows their tids.
52. Entry counts are drowned by heartbeats and certificates (no kind in the log); a latest-time register per child on the parent, written by posters, is the cheap source.
53. Threads and forum posts are reply chains inside the channel, grouped by the app.
54. A thing under the realm or holding a grant for it is in the realm; as a member of the realm's group it syncs under the realm's label, one with its own label syncs under that. With plain grants (notes/realms.md open question 1) a writer's removing it from the group only stops the auto-sync; removing it from the realm is an admin's grant removal.
55. Every thing's role history is kept forever and readable by its holders.
56. Rights: lower the top realm's role on each child, one commit per child; one step only as a client-honored flag.
