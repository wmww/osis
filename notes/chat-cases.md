# Chat test cases by architecture
> Summary: Informal chat behavior cases, each answered per proposed architecture (A, B, C, D, E): forced yes or no, app's choice, or needs a core change. Add a column per new topology; a good one has many `opt` and no `!`. Answers come from reading spec and code; column E was run where libs/chat/tests covers it; `want` values are guesses for Tess to correct.

Legend: **A** messages are things in the member's own group (untied read grant to the chat); **B** messages are things in the chat's member list, one-commit send; **C** messages are entries in a map on the member actor M (rolled to fresh M-owned things), with an add-only member list for non-admins (core change f). **D** (parked; review4 refuted its protection claim) is C plus a per-chat content key chain (core change i): content blobs wrapped under an hourly key erased after two hours, never in history boxes, re-seeded at every membership change. **E** (built: libs/chat, notes/chat.md) messages are writes on an aspect of the chat itself, kept as history (retention `author_or_admin`, keep at least forever: permanent deltas), no member actor and no member list, the sender the verified actor; E cells on kick cost assume the frontier study (notes/frontier-study.md), unbuilt; E1 (a register of message-thing tids) is noted only where it differs.
Cells: `yes`/`no` forced; `opt` app's clean choice; `opt*` a modified client defeats it; `core x` needs core change x (list at the end); `?` not traced; `–` not applicable; `!` marks a forced answer that differs from want. "Honest" means the party's client follows the rules; "modified" means it does not.
Assumed fixed (issues/): deposits of closure content, writer rotating to itself, header forgetting, rotation-name growth, the query API.

## Identity and authorship

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Can a member edit another member's message? | no | no | no | no | no | no |
| Can a chat admin edit another member's message? | no | no | no | no | no | no |
| Can a chat admin hide a message from honest clients? | yes | opt | opt | opt | opt | opt |
| Can a chat admin erase one message from hosts and honest devices? | yes | no! core b | no! core b | no! core b | no! core b | opt³⁸ |
| Can an admin of a member's account (their other device) edit that member's messages? | yes | yes | yes | yes | yes | yes |
| Can an admin of a team that is a member edit a team member's messages? | no | no | no | no | no | no |
| Can a member make a message appear as written by Bob? | no | no | opt¹ | no | no | no |
| Can a member make messages appear from a fake account that was never a member? | no | opt² | opt² | opt² | opt² | no |
| Does such a fake account's content cost every member storage until an admin removes it? | no | yes! | yes! | yes! | yes! | yes! |
| Does every reader see the verified sender of each message? | yes | yes | yes | yes | yes | yes |
| Can a member prove to outsiders that you wrote a message? | accepted | yes | yes | yes | yes | yes |
| Can a member purge another member's message? | no | no | no | no | no | no |

## A kicked member (honest client unless stated)

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Can they still read their own old messages? | yes | yes | yes | yes | yes | yes |
| Can they still read others' old messages? | opt | core c | core c | core c | core c | opt |
| Can they read new messages? | no | no | no | no | no | no |
| Can they post? | no | no | no | no | no | no |
| Modified client: can a post reach others through a host the kicker has not updated yet? | no | yes³! | no | yes³! | yes³! | no |
| Modified client: can a current member relay their post so it shows as theirs? | no | yes! | yes! | yes! | yes! | no |
| Modified client: can they edit or delete old messages so others see it? | no | yes³! | yes³! | yes³! | yes³! | no |
| Do others still see their old messages by default? | yes | opt | opt | opt | opt | opt |
| Can the kicker wipe their whole history from hosts and honest devices? | yes | yes | yes | yes | yes | yes²⁶ |
| Does their modified client keep what it downloaded? | accepted | yes | yes | yes | yes | yes |
| A message they sent before the kick that the kicker had not received: does it stay for others? | yes | yes | no! | yes | yes | no! |
| Kick without pre-sync: can the member's whole history drop from the list for everyone? | no | opt⁴ | opt⁴ | opt⁴ | opt⁴ | – |
| Re-added later: do posts their modified client made while kicked appear? | no | yes! | yes! | yes! | yes! | yes! |
| Re-added later: can they read what was sent while they were out? | opt | opt* | opt* | opt* | opt* | core n |

## Leaving

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| After leaving, can you read your own old messages? | yes | yes | yes | yes | yes | yes |
| After leaving, can you read others' old messages? | opt | core c | core c | core c | core c | opt |
| Do others still see your messages after you leave? | yes | opt | opt | opt | opt | opt |
| Can you delete your messages for everyone before leaving? | yes | yes | yes | yes | yes | yes |
| Can you delete your messages for everyone after leaving? | no | no | no | no | no | no |
| Modified client: can a leaver backdate a post before its leave so it stays? | no | yes³! | opt⁵ | yes³! | yes³! | opt⁵ |
| Does leaving wipe the chat from your device? | opt | core c | core c | core c | core c | opt |

## The member list

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Can a non-admin add a member? | opt | opt⁶ | opt⁶ | opt⁶ | opt⁶ | opt⁶ |
| Can a non-admin remove a member? | no | no | no | no | no | no |
| Can a non-admin remove another member's M, deleting their history at hosts? | no | yes! | yes! | no | no | – |
| Can a non-admin reset the whole list in one write? | no | yes! | yes! | no | no | – |
| Can a non-admin remove a single message from the list? | no | no | yes! | – | – | – |
| Does kicking the vandal undo their list changes? | yes | no! | no! | – | – | – |
| Can members see the member list? | yes | yes | yes | yes | yes | yes |
| Can members see each other's device lists? | accepted | yes | yes | yes | yes | yes |

## Adding

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Does a new member see the history? | opt | opt³³ | opt³³ | opt³³ | opt²¹ | opt³³ |
| Segments: can the new member's modified client learn anything about the earlier chat? | no | no³⁴ | no³⁴ | no³⁴ | no³⁴ | no³⁴ |
| Segments: two admins add different people at once; is the outcome deterministic with nothing lost for old members? | yes | yes³⁵ | yes³⁵ | yes³⁵ | yes³⁵ | yes³⁵ |
| Adding one member without history to a 1000-member group under 20 MB? | yes | yes³⁶ | yes³⁶ | yes³⁶ | yes³⁶ | yes³⁶ |
| Can strangers join by link with no admin online? | yes | yes | yes | yes | yes | yes |
| Does a link joiner keep access when the sharer is kicked? | yes | opt⁷ | opt⁷ | opt⁷ | opt⁷ | opt⁷ |
| Can an admin kick one link joiner without killing the link? | yes | opt⁷ | opt⁷ | opt⁷ | opt⁷ | opt⁷ |
| Does a stranger's invite show a verified sender before accepting? | yes | core e | core e | core e | core e | core e |
| Does a stranger's invite fetch anything before you accept? | no | no | no | no | no | no |

## Devices

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Does a new device get the full history? | yes | yes | yes | yes | yes³⁷ | yes |
| Does a kicked member's new device get that member's own messages? | yes | opt⁸ | opt⁸ | opt⁸ | opt⁸ | no! |
| Can a removed (lost) device read new messages? | no | no | no | no | no | no |
| Does removing a device wipe the chat from it (honest device)? | yes | yes | yes | yes | yes | yes |
| Two devices of one member post offline at once: do both messages appear? | yes | yes | yes | yes⁹ | yes⁹ | yes |

## Delete and disappear

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Delete for everyone: erased on honest online devices? | yes | yes | yes | yes | yes | yes |
| Erased on offline devices when they return? | yes | yes | yes | yes | yes | yes |
| Erased at hosts? | yes | yes | yes | yes | yes | yes |
| Attachments erased too? | yes | yes | yes | yes | yes | yes |
| Edit: does the old text leave hosts promptly? | yes | yes | yes | yes¹⁰ | yes¹⁰ | yes²⁷ |
| Disappearing message gone everywhere at its time, hosts unattended? | yes | yes | yes | yes | yes | yes |
| Offline device past the time: gone when it wakes? | yes | yes | yes | yes | yes | yes |
| Does a hostile device keep a deleted message? | accepted | yes | yes | yes | yes | yes |
| Can the app make messages undeletable (permanent chat)? | opt | opt* | opt* | opt* | opt* | opt* |
| Timer changed mid-chat: do old messages keep their old timer? | yes | yes | yes | yes | yes | yes |
| Does a disappeared message leave a trace on each device? | no | yes! | yes! | yes¹¹ | yes¹¹ | yes¹¹ |
| Does a deleted message leave the fact and time visible to members? | accepted | yes | yes | yes | yes | yes |

## Deletion traces (after a permanent delete)

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Does the app show a "message deleted" tombstone by default? | opt | opt | opt | opt | opt | opt |
| Can the app be set to show no trace at all? | opt | opt | opt | opt | opt | opt |
| Modified client: can it tell a message existed, who sent it and when, from what osis keeps? | accepted | yes | yes | yes¹⁸ | yes¹⁸ | yes²⁸ |
| Can a member forge a "Bob deleted a message" tombstone for a message Bob never sent? | no | no | yes¹⁹! | no | no | no |
| Can members tell an expired message from a purged one? | opt | opt²⁰ | opt²⁰ | opt²⁰ | opt²⁰ | opt²⁰ |
| Can a host tell that a message was deleted? | accepted | yes | yes | yes | yes | yes |
| Can a host tell who sent the deleted message, or what it said? | no | no | no | no | no | no |
| Can a host tell an expired entry from a purged one? | accepted | yes | yes | yes | yes | yes |
| Can a host forge a deletion that members show as a tombstone? | no | no | no | no | no | no |

## Moderation and abuse

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Modified member: can it write junk nobody can ever erase from hosts and honest devices? | no | no | no | no | no | no³¹ |
| Can admins wipe a member's whole history from hosts and devices? | yes | yes | yes | yes | yes | yes²⁶ |
| Can admins get one illegal message off hosts without wiping the member? | yes | no! core b | no! core b | no! core b | no! core b | opt³⁸ |
| Can you block someone without deleting anything on either side? | yes | opt | opt | opt | opt | opt |
| Is your evidence kept after blocking? | yes | opt | opt | opt | opt | opt |
| Can a blocked contact you share a group with add you to a chat? | no | opt¹² | opt¹² | opt¹² | opt¹² | opt¹² |
| Can a stranger holding your contact card fill your invite inbox? | no | yes¹³! | yes¹³! | yes¹³! | yes¹³! | yes¹³! |
| Do message requests show a verified sender? | yes | core e | core e | core e | core e | core e |

## Admins

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| No admin left: can members still post and leave? | yes | yes | yes | yes | yes | yes |
| No admin left: can anyone add or kick? | no | no | no | no | no | no |
| Last admin leaves: is someone promoted? | yes | opt | opt | opt | opt | opt |
| Two admins remove each other at once: one deterministic outcome? | yes | yes | yes | yes | yes | yes |
| Can a hostile sole admin wipe the chat for everyone? | accepted | yes | yes | yes | yes | yes |
| Can a writer lock everyone out by rotating keys to itself? | no | no | no | no | no | no |
| Can the creator leave or be demoted? | yes | yes | yes | yes | yes | yes |

## Hosts

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Does a host learn who is in the chat or what is said? | no | no | no | no | no | no |
| Does a host learn message sizes, times and expiries? | accepted | yes | yes | yes | yes | yes |
| Only host lost: can members move to a new one? | yes | opt¹⁴ | opt¹⁴ | opt¹⁴ | opt¹⁴ | opt¹⁴ |
| Members on different hosts of the chat: do they converge? | yes | yes | yes | yes | yes | yes |
| Can a host colluding with a kicked member read new messages? | no | no | no | no | no | no |
| Can a colluding host deliver a kicked member's post? | no | yes! | no | yes! | yes! | no |
| Can a member's own node host the chat? | yes | opt | opt | opt | opt | opt |

## Order and display

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Modified client: can a sender backdate a message into history? | no | yes! | yes! | yes! | yes! | yes! |
| Honest sender with a wrong clock: shown at a sane position? | yes | yes | yes | yes¹⁵ | yes¹⁵ | yes |
| Reply to a deleted message: shown as a placeholder? | yes | opt | opt | opt | opt | opt |
| Can a new device page recent history without downloading all of it? | yes | no! | opt¹⁶ | opt¹⁶ | opt¹⁶ | core o |
| Can the app show the latest 50 messages with the osis API alone? | yes | yes | yes | core g | core g | yes |
| Read receipts: can a member keep their read position private? | yes | opt | opt | opt | opt | opt |
| Typing: reaches connected devices only, stored nowhere? | yes | yes | yes | yes | yes | yes |
| Is a sender woken by its own post? | no | no | no | no | no | no |
| Notifications while the app is closed? | yes | core h | core h | core h | core h | core h |

## Costs

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Kick in a chat with a million messages under a minute of work on a phone? | yes | ? | ? | ? | ? | ?³² |
| Kick or lost device in a 1000-member group under 10 MB upload? | yes | yes | yes | yes | yes | yes⁴⁰ |
| Fresh device of a disappearing chat under 50 MB after 10 years at 100 a day? | yes | no! | no! | yes | yes | yes |
| Long-lived device of a permanent chat holds every message body? | yes | yes | yes | yes | yes | yes |
| Join under 100 KB? | yes | yes | yes | yes | yes | yes |
| A message under 3 KB on the wire? | yes | yes | yes | yes | yes | yes |
| New device of a 1000-member group under 100 MB before any message? | yes | yes | yes | yes | yes | yes |
| One edit after compaction under 1 MB of upload? | yes | yes | yes | yes¹⁷ | yes¹⁷ | yes |
| Compacting a member's history under 100 MB of memory on a phone? | yes | yes | yes | yes¹⁷ | yes¹⁷ | yes³⁰ |
| Is a send one commit? | yes | yes | yes | yes | yes | yes |

## Channels and 1:1

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Channel: only admins post, members read? | yes | yes | yes | yes | yes | yes |
| Channel: can read-only members react? | opt | no! | no! | no! | no! | no! |
| 1:1: the other side kicks you; do you keep their messages (honest client)? | yes | core c | core c | core c | core c | yes |
| 1:1: can either side kick the other? | no | opt* | opt* | opt* | opt* | opt* |
| Two 1:1 chats with one person created at once: shown as one? | yes | opt | opt | opt | opt | opt |

## Forward secrecy (a recording of the hosts plus one device stolen today)

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Can messages deleted or expired more than two hours ago be read? | no | yes! | yes! | yes! | yes³⁷! | yes! |
| Can messages deleted in the last two hours be read? | no | yes! | yes! | yes! | yes²³! | yes! |
| Can old messages the device no longer shows be read? | no | yes! | yes! | yes! | yes³⁷! | yes! |
| Stolen keys only: can messages sent after the theft be read? | no | yes! | yes! | yes! | yes³⁷! | yes! |
| Can a removed member read what it already copied? | accepted | yes | yes | yes | yes | yes |
| Does anyone gain deniability? | accepted | no | no | no | no | no |
| A device offline for a year: can it read everything still at the hosts on return? | yes | yes | yes | yes | yes | yes |
| Can a new member read history without an existing member re-publishing it? | opt | yes | yes | yes | no²¹ | yes |
| Do hosts end up storing content nobody can read? | no | no | no | no | opt²⁵ | no |
| Is protection per message, at once, rather than after a window? | yes | no! core j | no! core j | no! core j | no! core j | no! core j |
| Can a chat have forward secrecy at all? | yes | core m | core m | core m | no! core m | core m |
| Kick or lost device in a 1000-member group under 10 MB upload with forward secrecy? | yes | – | – | – | – | – |

## Realms (notes/realms.md: servers, teams and roles are realms; a channel is a chat a realm holds write on)

| case | want | A | B | C | D | E |
|---|---|---|---|---|---|---|
| Does removing a member from the top realm remove them from every channel at once? | yes | – | – | – | – | yes |
| Does one commit protect all new content from the removed member (channels re-key on the next sync)? | yes | – | – | – | – | yes⁴¹ |
| Does cutting the removed member's upload and sync keys need an admin step per channel per host? | no | – | – | – | – | yes⁴¹! |
| Can the removed member keep uploading junk to a channel until an admin steps it there? | no | – | – | – | – | yes! |
| Removal under 10 MB upload at 1000 members and 100 channels? | yes | – | – | – | – | yes⁴² |
| Removal under 10 MB upload at 100,000 members (nested rosters) and 100 channels? | yes | – | – | – | – | yes⁴² |
| Does a member's lost device or leave cost the next poster the top realm's whole rotation? | no | – | – | – | – | yes! |
| Is demoting a mod as cheap as a kick? | yes | – | – | – | – | no!⁴³ |
| Does each member's device download every other member's chains, cards and heartbeats under the top realm's label? | no | – | – | – | – | yes⁴⁴! core r |
| Kick pre-sync across 100 channels under a minute? | yes | – | – | – | – | ? |
| Can a mod mute one member in one channel while they hold the top realm? | yes | – | – | – | – | opt*⁴⁵ |
| Can a mod ban one member from one channel while they hold the top realm? | yes | – | – | – | – | no! |
| Can a mod time out a member for an hour? | yes | – | – | – | – | opt*⁴⁵ |
| Can a mod delete messages in some channels and not others? | yes | – | – | – | – | yes |
| Can a mod delete messages without also being able to lock the channel or change its roster? | yes | – | – | – | – | opt⁴⁶ |
| Can role holders add and remove others of their role? | opt | – | – | – | – | yes⁴⁷ |
| Read-only announcement channel where members can react? | yes | – | – | – | – | opt⁴⁸ |
| Does a read-only channel with 20 or more reader devices fill its deposit budget until a mod syncs? | no | – | – | – | – | yes! |
| Can any member create a channel that appears in the directory? | opt | – | – | – | – | opt⁴⁹ |
| Does the sidebar show channel names without reading each channel? | yes | – | – | – | – | yes⁵⁰ |
| Can non-members see that a private channel exists? | no | – | – | – | – | opt⁵¹ |
| Can a member post as a realm (the role actor)? | no | – | – | – | – | opt³⁹ |
| Can a member choose which channels to sync, with none by default? | yes | – | – | – | – | core s |
| Unread counts for channels not synced? | yes | – | – | – | – | opt⁵² |
| Mentions in channels not synced? | yes | – | – | – | – | core h |
| Threads without a new chat per thread? | yes | – | – | – | – | yes⁵³ |
| A document anyone in the realm can edit, synced to every member? | yes | – | – | – | – | yes⁵⁴ |
| Can a member remove another member's document from the realm's auto-synced content? | no | – | – | – | – | no⁵⁴ |
| The same chat in two realms? | yes | – | – | – | – | yes |
| Move a chat between realms without copying it? | yes | – | – | – | – | yes |
| A realm inside a realm, members inherited? | yes | – | – | – | – | yes |
| Is the kick and role history an audit log members can read? | yes | – | – | – | – | yes⁵⁵ |
| Realm-wide read-only mode in one step? | yes | – | – | – | – | opt*⁵⁶ |
| Per-member rate limits? | yes | – | – | – | – | no! |
| A realm with no admin left: posting still works? | yes | – | – | – | – | yes |

## Core changes

- **b** Delegated purge: retention names an actor whose admins may purge; binds only senders whose client wrote it.
- **c** Keep-after-removal: whether a removed holder keeps what it held is what its removal says, filled from a default on the thing unless the remover overrides (spec/permissions.md §2, §3 Keep); chat sets keep at creation (Tess); a person holds none, so a device removal erases.
- **e** Sender card in invite requests (Tess: yes).
- **f** Add-only member list (C only): a new core aspect read as a group's member list; a non-admin delta may hold only new elements, and resets and snapshots need admin. Assumed in every C cell.
- **g** Entry-level API: key-range read, change events naming the keys touched, per-entry received time.
- **h** Wake relay for background notifications (Tess: does not block).
- **i** Content key chain (D only): a boxed seed with no history box, re-seeded in every read rotation; an hourly hash-chain key in the clear prefix; content blobs wrapped under it; devices erase hour keys after two hours and keep blob keys of retained bodies; content older than the window is may-hold; a re-wrapped transfer bundle for new devices. Assumed in every D cell. Refuted by review4: the seed's box is in the recording and opens under keys the device keeps, so a thief rebuilds every hour key; only "newcomers cannot read older content" survives.
- **j** Per-sender key chains (Signal sender keys): per-message erasure, at the cost of a per-sender state per device and either a per-sender marker hosts can link or trial decryption.
- **k** Purge by author: a purge item naming (aspect, author) so an admin erases a removed member's deltas in one item, within each delta's own purge rights; never overrides author-only or `nobody` (Tess; spec/wire.md §4).
- **m** Erasable per-device KEM keys with per-device boxes (MLS-sized): what real member forward secrecy would need; against spec/crypto.md §3 and requirements line 48.
- **l** History read API (E): the held bodies of an aspect with author, time, received time, validity and the sender flag, paged by time, memory commits included, and a change event per commit.
- **n** History-less grant: a read rotation at the add with earlier secrets sealed per prior holder, no shared history box, chain certificates re-placed (issues/history-less-grant.md); segments (footnote 33) are the fallback without core change.
- **o** Newest-first fetch of a label: built (spec/sync.md §6); a device that stops fetching: issues/partial-history-fetch.md.
- **p** Verified actor: a commit is invalid unless its author could write as its `actor` (built: spec/permissions.md §5.2, Acting).
- **r** Pure readers place nothing under big labels: no chain certificates, node card or heartbeats from a reader unless asked (realms past a few thousand members).
- **s** Default-off sync: a device holding a realm's secret does not sync the labels of the things the realm holds until the app chooses (today `compute_labels` syncs every label whose secret the node holds).
- **q** Purge sets: `author` (admins cannot purge) is a setting beside `admin` and `nobody` (spec/commits.md §5).

## Footnotes

1. B: an empty thing owned by Bob's M can be placed; the app hides messages without a valid text.
2. Hidden by the "ever held write on the chat" check, not stopped; costs storage until an admin removes its M.
3. Only through a host the kicker has not reached or that refused the step, or a relaying member; honest members then re-upload it (requirements line 124).
4. `WaitForSync::Required` (default) covers the join add; `Skip` does not.
5. B: once an admin writes an explicit removal of the absent edge, the leave is audited and the post is unlisted.
6. An admin gives member grants an `invite` level; then members may invite.
7. Only if the sharer's device granted the joiner directly on join (links are admin-only).
8. Only if M is also added to the member's home group.
9. C: with map keys (wall ms, random bytes); a sequence counter would merge the two.
10. C: after compaction the old text stays in the map snapshot for up to 1 h and the whole map is rewritten.
11. C: about 33 B of value-less residue per message; closable (issues/valueless-gaps.md).
12. The grant applies (sender is "connected"); the app leaves automatically.
13. Needs your contact card's keys; the remedy is a new card.
14. Needs two hosts listed, or direct member-to-member contact, for the replacement to be learned.
15. C: the per-entry received time is not readable today (part of g).
16. Per-year sub-groups owned by the chat, each with its own label; in C the year group must use the add-only list aspect.
17. C: with rolling at about 10,000 entries per thing (snapshot rewrite is O(map)).
18. A/B: the message thing's creation record and first header stay forever (sender's M, time). C: the value-less stamp (sender's device, time) stays as residue; the header until forgotten.
19. B: an empty thing owned by Bob's M can be placed; it differs from a real deletion only while the purged commit's header-only blob or Bob's purge request is still held (purge commits are kept `ROLE_KEEP`).
20. From held headers: an expired delta carries `expires`, a purged one is named by a purge request; after header forgetting both are residue.
21. D: history is unreadable to a joiner unless an existing member re-publishes it under the current hour key; it is then exposed for two hours like fresh traffic.
22. D: by a transfer bundle from an old device over a direct connection, re-wrapped under the current hour key; without one, none.
23. D: the window is the current and previous hour (`MAX_DRIFT`); below it in-flight uploads become unreadable.
24. D: a forward hash chain; cut off at the next membership change, or by an optional periodic re-seed (1.2 KB per member each).
25. D: the uploader attaches a timed host delete, or the chat uses expiry; otherwise old content stays unreadable dead weight.
26. E: for messages written with the requested retention; a modified sender's `nobody` message is hidden and stored for good, unless a required retention refuses it (issues/required-retention.md).
27. E: an edit is a new message plus a purge of the old one.
28. E: the header-only blob of a purged permanent delta is kept forever and reaches new devices, with its purge commit (spec/commits.md §5); E1 keeps the tid and time forever by design.
29. E: per-year things owned by the chat, each synced under its own label.
30. E: nothing is compacted; messages keep at least forever.
31. E: a required retention on every aspect makes `nobody` junk invalid, dropped without a right (spec/permissions.md §7); junk under the required retention is what purge by author erases; a member from before a change can still backdate below it.
32. E: the frontier is a few heads (frontier study), but un-merging a kicked member's deltas re-reads the year's aspect (about 70 s at 10^6, extrapolated, e-review §6); not measured in any design.
33. Segments: the admin creates a new chat, grants everyone plus the newcomer, and the old chat points to it (admin-only); old members' apps stitch the two. Works in every design, no core change; Tess's primary path is core n.
34. The new chat carries no pointer back; a tid is a bare reference and the old chat's label and hosts live under its own label.
35. The pointer is a set, so old members stitch every branch; each newcomer sees only its branch; admins merge with a further segment.
36. About 15 KB per member (grant boxes plus chain certificates under the new label): about 15 MB at 1000, estimated.
37. D as written: the chain seed's box is in the recording, sealed to a key the device keeps, so a thief rebuilds every hour key (review4).
38. E: default yes; author-only purge (admins cannot delete) is a chat setting (core q, built).
39. E: the header's actor is checked by validity (spec/permissions.md §5.2: the signing device holds write on the actor at the commit's key), so a valid commit's actor is its sender; that the actor itself could write on the chat is the ordinary validity of the device's write only when its path runs through the actor.
40. E: with the frontier study; today a kick lists about 34 B per message the member ever sent (3.4 MB at 10^5) and caps near 1.9x10^6 messages.
41. The removal and the top realm's rotation are one commit (2.7 KB per member); each child re-keys on any writer's next sync pass (about 11 KB, eager, may fork). Cutting sync, write and deposit keys needs an admin of each child to register a step at each host; until then the removed member reads ciphertext and can upload.
42. At 1000: 2.7 MB plus about 11 KB per child, spread over members' passes. At 100,000 with tiers of 1000: the tier (2.7 MB), the top realm (100 boxes), then children; estimated, and only with issues/keyset-names-placement-rosters.md fixed.
43. All three roles rotate on every realm and chat the mod administered, admins only; the ex-mod keeps delete keys until each label is stepped.
44. Every syncing device places its chain (11.5 KB per person), card (1.5 KB) and four heartbeats a day under each label it reads: about 13 MB once and 2.4 MB a day at 1000; about 1.4 GB and 240 MB a day at 100,000 (e-realms-review.md §3).
45. By rights no: a role is the maximum over paths and `until` only ends a grant. Mods write a muted set with a time; honest clients hide and mods purge; a modified client posts on.
46. Messages on a thing owned by the chat with an admin edge for the delete role (spec/permissions.md §1): purge without roster or lock; one more rotation per kick.
47. Admin passes only through admin, and admins of a realm manage its roster; direct per-channel admin grants avoid it at one grant per channel.
48. A sibling chat the members write carries the reactions; the app shows them under the announcement.
49. Adding a channel is a grant for the realm on the chat, needing admin on the chat and on the realm's layout; a member creates a chat and asks an admin to add it.
50. The realm's edges are its contents (every member holds them through the realm's inbox copies); names and categories are a chat-app layout aspect on the realm. Channels are not in the realm's group, so nothing of theirs is under its label.
51. Grant the private channel only to a role realm. Left: its hosts see its label, a device-removal frontier head names its tid under public labels (frontier-study format), and a purge across children shows their tids.
52. Entry counts are drowned by heartbeats and certificates (no kind in the log); a latest-time register per child on the parent, written by posters, is the cheap source.
53. Threads and forum posts are reply chains inside the channel, grouped by the app.
54. A thing owned by the realm or holding an edge for it is in the realm; placed in the realm's group it syncs under the realm's label, one with its own label syncs under that. With plain edges (notes/realms.md open question 1) a writer's unplacing only stops the auto-sync; removing it from the realm is an admin's edge removal.
55. An ownerless actor has no roster snapshots, so its role history is kept forever and readable by its holders.
56. Rights: demote the top realm on each child, one commit per child; one step only as a client-honored flag.
