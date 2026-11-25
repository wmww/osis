# Chat cases
> Summary: Informal chat behavior cases with what chat (design E, notes/chat.md) answers: forced yes or no, app's choice, or needs a core change; `want` values are guesses for Tess to correct. Answers come from reading spec and code, run where libs/chat/tests covers them. Check a new chat topology against these.

Cells: `yes`/`no` forced; `opt` app's clean choice; `opt*` a modified client defeats it; `core x` needs core change x (list at the end); `?` not traced; `!` marks a forced answer that differs from want. "Honest" means the party's client follows the rules; "modified" means it does not. Kick cost cells assume frontier heads, a dropped design (frontiers list IDs: notes/revocation.md, Frontier encoding). Assumed fixed (issues/): writer rotating to itself (removing it recovers, notes/keys.md Lockouts), header forgetting, rotation-name growth, the query API.

## Identity and authorship

| case | want | chat |
|---|---|---|
| Can a member edit another member's message? | no | no |
| Can a chat admin edit another member's message? | no | no |
| Can a chat admin hide a message from honest clients? | yes | opt |
| Can a chat admin erase one message from nodes keeping the chat unread and honest nodes? | yes | opt³⁸ |
| Can an admin of a member's account (their other node) edit that member's messages? | yes | yes |
| Can an admin of an organization that is a member edit the messages of the organization's members? | no | no |
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
| Modified client: can a post reach others through a node keeping the chat unread that the kicker has not updated yet? | no | no |
| Modified client: can a current member relay their post so it shows as theirs? | no | no |
| Modified client: can they edit or delete old messages so others see it? | no | no |
| Do others still see their old messages by default? | yes | opt |
| Can the kicker wipe their whole history from nodes keeping the chat unread and honest nodes? | yes | yes²⁶ |
| Does their modified client keep what it downloaded? | accepted | yes |
| A message they sent before the kick that the kicker had not received: does it stay for others? | yes | no! |
| Re-added later: do posts their modified client made while kicked appear? | no | yes! |
| Re-added later: can they read what was sent while they were out? | opt | opt³³ |

## Leaving

| case | want | chat |
|---|---|---|
| After leaving, can you read your own old messages? | yes | yes |
| After leaving, can you read others' old messages? | opt | opt |
| Do others still see your messages after you leave? | yes | opt |
| Can you delete your messages for everyone before leaving? | yes | yes |
| Can you delete your messages for everyone after leaving? | no | no |
| Modified client: can a leaver backdate a post before its leave so it stays? | no | opt⁵ |
| Does leaving wipe the chat from your node? | opt | opt |

## The member list

| case | want | chat |
|---|---|---|
| Can a non-admin add a member? | opt | opt⁶ |
| Can a non-admin remove a member? | no | no |
| Can members see the member list? | yes | yes |
| Can members see each other's node lists? | accepted | yes |

## Adding

| case | want | chat |
|---|---|---|
| Does a new member see the history? | opt | opt³³ |
| Adding one member without history to a 1000-member group under 20 MB? | yes | ? |
| Can strangers join by link with no admin online? | yes | yes |
| Does a link joiner keep access when the sharer is kicked? | yes | opt⁷ |
| Can an admin kick one link joiner without killing the link? | yes | opt⁷ |
| Does a stranger's offer show a verified sender before you hold the thing? | yes | core e |
| Does a stranger's offer fetch anything before you hold the thing? | no | no |

## Nodes

| case | want | chat |
|---|---|---|
| Does a new node get the full history? | yes | yes |
| Does a kicked member's new node get that member's own messages? | yes | no! |
| Can a removed (lost) node read new messages? | no | no |
| Does removing a node wipe the chat from it (honest node)? | yes | yes |
| Two nodes of one member post offline at once: do both messages appear? | yes | yes |

## Delete and disappear

| case | want | chat |
|---|---|---|
| Delete for everyone: erased on honest online nodes? | yes | yes |
| Erased on offline nodes when they return? | yes | yes |
| Erased at nodes keeping the chat unread? | yes | yes |
| Attachments erased too? | yes | yes |
| Edit: does the old text leave nodes keeping the chat unread promptly? | yes | yes²⁷ |
| Disappearing message gone everywhere at its time, with the nodes keeping the chat unread unattended? | yes | yes |
| Offline node past the time: gone when it wakes? | yes | yes |
| Does a hostile node keep a deleted message? | accepted | yes |
| Can the app make messages undeletable (permanent chat)? | opt | no!³⁸ |
| Timer changed mid-chat: do old messages keep their old timer? | yes | yes |
| Does a disappeared message leave a trace on each node? | no | yes¹¹ |
| Does a deleted message leave the fact and time visible to members? | accepted | yes |

## Deletion traces (after a permanent delete)

| case | want | chat |
|---|---|---|
| Does the app show a "message deleted" tombstone by default? | opt | opt |
| Can the app be set to show no trace at all? | opt | opt |
| Modified client: can it tell a message existed, who sent it and when, from what osis keeps? | accepted | yes²⁸ |
| Can a member forge a "Bob deleted a message" tombstone for a message Bob never sent? | no | no |
| Can members tell an expired message from a purged one? | opt | opt²⁰ |
| Can a node keeping the chat unread tell that a message was deleted? | accepted | yes |
| Can a node keeping the chat unread tell who sent the deleted message, or what it said? | no | no |
| Can a node keeping the chat unread tell an expired entry from a purged one? | accepted | yes |
| Can a node keeping the chat unread forge a deletion that members show as a tombstone? | no | no |

## Moderation and abuse

| case | want | chat |
|---|---|---|
| Modified member: can it write junk nobody can ever erase from nodes keeping the chat unread and honest nodes? | no | no³¹ |
| Can admins wipe a member's whole history from nodes keeping the chat unread and nodes? | yes | yes²⁶ |
| Can admins get one illegal message off nodes keeping the chat unread without wiping the member? | yes | opt³⁸ |
| Can you block someone without deleting anything on either side? | yes | opt |
| Is your evidence kept after blocking? | yes | opt |
| Can a blocked contact you share a group with add you to a chat? | no | opt¹² |
| Can a stranger holding your contact card fill your inbox with offers? | no | yes¹³! |
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

## Nodes keeping the chat unread

| case | want | chat |
|---|---|---|
| Does a node keeping the chat unread learn who is in the chat or what is said? | no | no |
| Does a node keeping the chat unread learn message sizes, times and expiries? | accepted | yes |
| Only node keeping the chat unread lost: can members move to a new one? | yes | opt¹⁴ |
| Members on different nodes keeping the chat unread: do they converge? | yes | yes |
| Can a node keeping the chat unread, colluding with a kicked member, read new messages? | no | no |
| Can a node keeping the chat unread, colluding, deliver a kicked member's post? | no | no |
| Can a member's own node serve the chat? | yes | opt |

## Order and display

| case | want | chat |
|---|---|---|
| Modified client: can a sender backdate a message into history? | no | yes! |
| Honest sender with a wrong clock: shown at a sane position? | yes | yes |
| Reply to a deleted message: shown as a placeholder? | yes | opt |
| Can a new node page recent history without downloading all of it? | yes | core o |
| Can the app show the latest 50 messages with the osis API alone? | yes | yes |
| Read receipts: can a member keep their read position private? | yes | opt |
| Typing: reaches connected nodes only, stored nowhere? | yes | yes |
| Is a sender woken by its own post? | no | no |
| Notifications while the app is closed? | yes | core h |

## Costs

| case | want | chat |
|---|---|---|
| Kick in a chat with a million messages under a minute of work on a phone? | yes | ?³² |
| Kick or lost node in a 1000-member group under 10 MB sent? | yes | yes⁴⁰ |
| Fresh node of a disappearing chat under 50 MB after 10 years at 100 a day? | yes | yes |
| Long-lived node of a permanent chat holds every message body? | yes | yes |
| Join under 100 KB? | yes | yes |
| A message under 3 KB on the wire? | yes | yes |
| New node of a 1000-member group under 100 MB before any message? | yes | yes |
| One edit after compaction under 1 MB sent? | yes | yes |
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

## Forward secrecy (a recording of the nodes keeping the chat unread plus one device stolen today)

| case | want | chat |
|---|---|---|
| Can messages deleted or expired more than two hours ago be read? | no | yes! |
| Can messages deleted in the last two hours be read? | no | yes! |
| Can old messages the node no longer shows be read? | no | yes! |
| Stolen keys only: can messages sent after the theft be read? | no | yes! |
| Can a removed member read what it already copied? | accepted | yes |
| Does anyone gain deniability? | accepted | no |
| A node offline for a year: can it read everything still at the nodes keeping the chat unread on return? | yes | yes |
| Can a new member read history without an existing member re-publishing it? | opt | yes |
| Do nodes keeping the chat unread end up storing content nobody can read? | no | no |
| Is protection per message, at once, rather than after a window? | yes | no! core j |
| Can a chat have forward secrecy at all? | yes | core m |

## Realms (notes/realms.md)
Nothing here is designed: each answer is what today's core would give if servers, organizations and roles were realms as notes/realms.md proposes (a channel a chat a realm holds write on).

| case | want | chat |
|---|---|---|
| Does removing a member from the top realm remove them from every channel at once? | yes | yes |
| Does one commit protect all new content from the removed member (channels re-key on the next sync)? | yes | yes⁴¹ |
| Does cutting the removed member's write and sync keys need an admin step per channel per node keeping the chat unread? | no | yes⁴¹! |
| Can the removed member keep writing junk to a channel until an admin steps it there? | no | yes! |
| Removal under 10 MB sent at 1000 members and 100 channels? | yes | yes⁴² |
| Removal under 10 MB sent at 100,000 members (nested rosters) and 100 channels? | yes | yes⁴² |
| Does a member's lost node or leave cost the next poster the top realm's whole rotation? | no | yes! |
| Is demoting a mod as cheap as a kick? | yes | no!⁴³ |
| Does each member's node download every other member's chains and cards under the top realm's sync ID? | no | yes⁴⁴! core r |
| Kick pre-sync across 100 channels under a minute? | yes | ? |
| Can a mod mute one member in one channel while they hold the top realm? | yes | opt*⁴⁵ |
| Can a mod ban one member from one channel while they hold the top realm? | yes | no! |
| Can a mod time out a member for an hour? | yes | opt*⁴⁵ |
| Can a mod delete messages in some channels and not others? | yes | yes |
| Can a mod delete messages without also being able to lock the channel or change its roster? | yes | opt⁴⁶ |
| Can role holders add and remove others of their role? | opt | yes⁴⁷ |
| Read-only announcement channel where members can react? | yes | opt⁴⁸ |
| Does a read-only channel with 20 or more reader nodes fill its deposit budget until a mod syncs? | no | yes! |
| Can any member create a channel that appears in the directory? | opt | opt⁴⁹ |
| Does the sidebar show channel names without reading each channel? | yes | yes⁵⁰ |
| Can non-members see that a private channel exists? | no | opt⁵¹ |
| Can a member post as a realm (the thing its path acts on)? | no | opt³⁹ |
| Can a member choose which channels to sync, with none by default? | yes | opt⁵⁰ |
| Unread counts for channels not synced? | yes | opt⁵² |
| Mentions in channels not synced? | yes | core h |
| Threads without a new chat per thread? | yes | yes⁵³ |
| A document anyone in the realm can edit, synced to every member? | yes | yes⁵⁴ |
| Can a member remove another member's document from the realm's auto-synced content? | no | opt⁵⁴ |
| The same chat in two realms? | yes | yes |
| Move a chat between realms without copying it? | yes | yes |
| A realm inside a realm, members inherited? | yes | yes |
| Is the kick and role history an audit log members can read? | yes | yes⁵⁵ |
| Realm-wide read-only mode in one step? | yes | opt*⁵⁶ |
| Per-member rate limits? | yes | no! |
| A realm with no admin left: posting still works? | yes | yes |

## Core changes

- **e** Sender card in offers from strangers (Tess: yes).
- **h** Wake relay for background notifications (Tess: does not block).
- **j** Per-sender key chains (Signal sender keys): per-message erasure, at the cost of a per-sender state per node and either a per-sender marker the nodes keeping the chat unread can link or trial decryption.
- **m** Erasable per-node KEM keys with per-node boxes (MLS-sized): what real member forward secrecy would need; against spec/crypto.md §3 and spec/requirements.md, Cost.
- **o** A node that stops fetching short of old messages (issues/partial-history-fetch.md); fetch is newest first (spec/sync-judgement.md §2).
- **r** Pure readers place nothing under big sync IDs: no certificate copies or node card from a reader unless asked (realms past a few thousand members).

## Footnotes

5. Once an admin writes an explicit removal of the absent grant, the leave is audited and the post is unlisted.
6. An admin gives member grants the may-grant flag; then members may invite.
7. Only if the sharer's node granted the joiner directly on join (links are admin-only).
11. Its header, until forgotten; none of its writes stays (spec/crdt.md §4.7).
12. The grant is the chat's own data and applies whoever wrote it; the app leaves automatically.
13. Needs your contact card's keys; the remedy is a new card.
14. Needs two nodes keeping the chat unread listed, or direct member-to-member contact, for the replacement to be learned.
20. From held headers: an expired delta carries `expires`, a purged one is named by a purge request; after header forgetting both are residue.
26. admins may always purge (spec/commits.md §5 Who and how long): a modified sender's message goes like any.
27. an edit is a replacement of the message purging its older versions in the same commit.
28. the header-only blob of a purged permanent delta is kept forever and reaches new nodes, with its purge commit (spec/commits.md §5).
30. nothing is compacted; messages keep at least forever.
31. admins may always purge (spec/commits.md §5 Who and how long): junk is what an admin's purge by author erases.
33. The grant's `reads` (`GrantOpts::reads`: `FromNow` or `All`; notes/history-less-grant.md). Segments, a chain of chats, are rejected (notes/chat.md Left out).
38. admins may always purge (spec/commits.md §5): no setting makes a message undeletable.
39. the purge author is a member of every thing's stated path, so validity checks it (notes/path-form.md, Whom a write is by): a valid commit's purge author is its sender.
40. with frontier heads (unbuilt); without them a kick lists about 34 B per message the member ever sent (3.4 MB at 10^5) and caps near 1.9x10^6 messages.
41. The removal and the top realm's rotation are one commit (2.7 KB per member); each channel re-keys on any writer's next sync pass (about 11 KB, eager, may fork). Cutting sync, write and deposit keys needs an admin of each channel to register a step at each node keeping it unread; until then the removed member reads ciphertext and can log entries.
42. At 1000: 2.7 MB plus about 11 KB per channel, spread over members' passes. At 100,000 with tiers of 1000: the tier (2.7 MB), the top realm (100 boxes), then channels; estimated.
43. All three roles rotate on every realm and chat the mod administered, admins only; the ex-mod keeps delete keys until each sync ID is stepped.
44. Every syncing node logs its chain (11.5 KB per account) and card (1.5 KB) under each sync ID it reads: about 13 MB once at 1000; about 1.4 GB at 100,000.
45. By rights no: a role is the maximum over paths and `until` only ends a grant. Mods write a muted set with a time; honest clients hide and mods purge; a modified client posts on.
46. Messages on a thing minted with admin the chat, with an admin grant for the delete role (spec/permissions.md §1): purge without roster or lock; one more rotation per kick.
47. Admin passes only through admin, and admins of a realm manage its roster; direct per-channel admin grants avoid it at one grant per channel.
48. A sibling chat the members write carries the reactions; the app shows them under the announcement.
49. Adding a channel is a grant for the realm on the chat, needing admin on the chat and on the realm's layout; a member creates a chat and asks an admin to add it.
50. Names and categories are a chat-app layout aspect on the realm, naming each channel by a weak, so nothing of a channel is in the realm's sync unit; a member's app syncs a channel by holding a strong to it (spec/sync-set.md §1).
51. Grant the private channel only to a role realm. Left: the nodes keeping it unread see its sync ID, a node-removal frontier head names its tid under public sync IDs (frontier-study format), and a purge across channels shows their tids.
52. Entry counts are drowned by certificates (no kind in the log); a latest-time register per channel on the realm, written by posters, is the cheap source.
53. Threads and forum posts are reply chains inside the channel, grouped by the app.
54. A thing the realm reads (minted with it as admin, or granted to it) is in the realm's sync unit while a strong on the realm references it; an independent one syncs under its own sync ID too. Whether writers may remove one is the realm schema's choice (Tess): strongs in an admin-only aspect (`^`, spec/data-model.md §2) only admins remove; in `holds.0` any member may, and the thing leaves the realm's sync unit, going where nothing else references it (spec/sync-set.md §3).
55. Every thing's role history is kept forever and readable by its holders.
56. Rights: lower the top realm's role on each channel, one commit per channel; one step only as a client-honored flag.
