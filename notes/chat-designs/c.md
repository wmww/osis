# Chat design C: messages as entries on the member actor
> Summary: A chat C is an actor, group and label owned by a thrown-away key; members are accounts with write on C, admins have admin; each member has one member actor M (owned by its account, C granted read on it, not tied) whose map aspect holds that member's messages as entries; C's member list is add-only for non-admins (a core change). Sender-only edit and purge, no per-message thing or list element, moderation by hide and wipe, kicked members stopped by the upload stamp, forward secrecy not included (design D adds it).

## What is different

No shared set lists messages and no thing exists per message. A message is an entry in `chat:msgs.0` on M, keyed by (wall time, random bytes). Reactions and replies refer to (M, key). When a map passes about 10,000 live entries the app rolls to a fresh thing owned by M and listed in M's own group; M is in C's list as item and subgroup from the start, so the closure follows. M is also added to the member's home group, so the member's own devices keep their history after a kick or leave.

## Permissions and topology

| thing | owner | roles on it | written by |
|---|---|---|---|
| C: actor, group, label; `chat:settings.0^` (name, timer), `chat:hidden.0^`; add-only member list of M's | burned key | members: write; admins: admin | members add their own M; admins add or remove any |
| M: actor, group; `chat:msgs.0` (map of messages), nick, reactions, read marker (memory), typing (signal); its group lists rolled message things | the member's account | C: read, not tied | the member's devices |

Who sent this, one rule: a message is shown as sent by the account owning its M, only when C is on M's roster and that account holds or ever held write on C. A fake account's M is hidden, not stopped, and costs storage until an admin removes it.

## Common operations

- **Add.** Grant the account write on C (from a contact card or shared group). Its device makes M, adds it to C's list and to its home group, grants C read on M. Members may invite if the admin gave their grant an invite level; links are admin-only and the sharer's device grants each joiner directly on join.
- **Send.** One commit, one delta: the entry. About 2 KB on the wire. Attachments are blobs in the entry, fetched lazily; their sizes are in the entry.
- **Edit, delete.** `chat:msgs.0` has one retention for the whole aspect: `writer`, keep at most 0 after replaced; only the sender's devices are writers. An edit is remove plus put in one commit, so the old text drops at once while uncompacted; after compaction it stays in the map snapshot for up to an hour and the whole map is rewritten. Delete for everyone is a reset plus purge request. Delete before leaving: afterwards there is no stamp.
- **Disappearing.** The timer in `chat:settings.0^`; the sender sets `expires` on the entry; reactions get the same time. Hosts delete at the time unattended.
- **Moderation.** Admins hide by (M, key) in `chat:hidden.0^`; an honest sender's client purges a hidden message. Admins wipe a member by removing C's read on M. There is no admin erase of one message.
- **Kick.** `demote(C, account, Remove)` after syncing C's label; one commit with C's rotation (2.7 KB per remaining member), re-registration at each host, removal of the member's links. Writes on M stay valid, so a modified client can still post or edit through a host the kicker has not updated or a relaying member (requirements line 124); honest members re-upload what gets through. The kicked device drops others' messages, keeps its own; a keep-read-only policy is a core change.
- **Leave.** Self-removal; an admin follows with an explicit removal of the absent grant so backdated posts are audited; the next writer rotates.
- **Block.** Local: hide, mute, auto-decline, leave chats the blocked account adds you to. Nothing deleted.
- **Hosts.** Any open host or a member's node listing C's label (the burned owner is nobody's person, so own-admission does not cover it). List two.
- **Deletion traces.** Osis keeps the fact, sender device and time of a deleted entry; whether the app shows a tombstone is a product choice.

## Core changes needed

- **Add-only member list:** a new core aspect read as the member list for the closure; a non-admin delta holds only new elements; resets and compaction snapshots need admin. Required: without it one member's write makes hosts delete another member's history.
- **Entry-level API:** key-range read, change events naming the keys touched, per-entry received time.
- **Keep-read-only policy on removal** (product choice for kicked and leaving members, never for device removal).
- **Sender card in invite requests** (Tess: yes). **Wake relay** (Tess: does not block).
- Considered and dropped: delegated purge for moderators (binds only honest senders, so it matches hide plus cooperative purge).

## Sorting into Tess's categories

- **Default in the default app:** kicked members keep own messages and others keep their history; block is local; disappearing timer per chat; edits leave no old text; deletion shows a tombstone.
- **Setting:** wipe on kick; show no deletion trace; read position private; members may invite; permanent chat (`nobody` retention, honest clients only).
- **Not exposed, clean for another app:** channels (admins write, members read); per-year chat-owned sub-labels for paging; longer rolling threshold.
- **Incompatible:** admins erasing one message's bytes; stopping a kicked member's late writes by rule; readers reacting in a channel; per-message protection against a host recording (design D).
