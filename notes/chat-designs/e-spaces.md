# Chat design E: spaces
> Summary: A Discord- or Slack-style space over E chats with existing primitives: a space is a group listing channels (listing grants nothing) plus ownerless role actors; "everyone" holds the members, channels grant roles to role actors, so membership is inherited by nesting and one removal is one commit, each channel re-keyed lazily by its next poster. Not expressible: a per-channel deny for someone who holds "everyone", a mod who deletes but cannot also lock the channel or manage its role, per-member rate limits. Worst cost: at 100,000 members every device downloads every other device's card. Citations: `e-spaces-evidence.md`.

**Status:** reviewed, corrections pending; e-spaces-review.md overrides this file where they differ.

## Shape

- **Channel:** exactly an E chat, an ownerless actor C with its own label.
- **Space:** a group S listing the channels (sub-lists for categories), readable by members, written by mods only, so nobody unlists another's channel.
- **Role actors:** ownerless actors. "Everyone" (EV) holds the members as writers. A public channel grants EV write, an announcement channel read, a private channel only its role actors or people. Mods hold admin on MODS, which holds admin on channels: a role's power on a path is the minimum along it, so admin can only pass through admin.
- **Audit log:** EV's role history, kept forever (an ownerless actor has no roster snapshots), readable by every member.

## Removal, the crux (traced; numbers estimated)

Removing a member from EV is one commit: the edge removal plus EV's rotation, 2.7 KB per holder (2.7 MB at 1000). Every channel EV opens must rotate too, but lazily: the next member to post in a channel rotates it, one small commit sealed to the channel's few holder actors (about 7 KB); a channel nobody posts in never rotates and leaks nothing new. 100 channels cost about 0.7 MB spread over posters, with no kicker work and no half-done state. Only a channel admin registers new keys at hosts, so until a mod syncs each channel the removed member keeps a stale sync key there (ciphertext only). The kick's frontier covers the member's posts in every channel: a few 60-byte heads per channel it wrote in (frontier study, unbuilt); the kicker's pre-sync reads 100 labels' headers.

At 100,000 members the roster nests: EV holds 100 tier actors of 1000. A removal rotates the tier (2.7 MB), then EV (100 boxes), then channels lazily. But every member reads EV's label for EV's secrets, and every tracking device places its node card there: about 1.5 KB per device, about 200 MB per member device. That is the worst cost; it needs a core option to skip cards on huge labels.

Joining: one grant (2.7 KB), chain certificates under EV's label and each channel the joiner posts in (11.5 KB each), a card per label it reads.

## Permissions a Discord user expects

- **Inherited roles, no deny.** A role is the maximum over paths, so a member holding EV cannot be muted or banned in one channel by rights. Replacement: a channel-level muted set written by mods; honest clients hide, mods purge, a modified client still posts. Timeouts: `until` on the EV grant, space-wide. Real per-channel exclusion means a posting role per channel set instead of EV, whose removals cost that role's roster size.
- **Mods.** Admin on a channel is one bundle: delete, lock, roster, settings. "Delete but not lock" is not expressible. Admins of MODS add and remove each other; direct per-channel admin grants avoid that at one grant per channel.
- **Announcements with reactions:** EV reads C; reactions are writes, so a sister chat where EV writes carries them.
- **Private channel existence:** a listing shows every reader the tid; put private channels in a sub-list whose own label only the role reads.
- **Invites:** `invite` levels and links on EV, as in E. **Posting as "everyone":** the sender rule shows only actors that are accounts.

## Sync

A node syncs the labels it chooses; holding EV forces nothing. Default: sync the list and EV, open a channel's label on view, keep pinned ones, mute by not syncing. Unread counts for unsynced channels: new entries since the cursor, once partial fetch exists (approximate). Mentions need bodies: the wake relay wakes the device per label. Search is local.

## Threads, pins, categories, DMs

Threads and forum posts are reply chains inside the channel, grouped by the app: no new actor. Pins: an admin-only set on the channel. Categories: sub-lists. Per-user order and mutes: the member's own data. DMs: 1:1 E chats, untouched.

## Composability and moderation

A chat in two spaces is listed in both and grants both EV actors; moving it edits lists and grants, nothing is owned, so no copy. A space inside a space: S1's EV granted write on S2's EV. Personal tags work as for any thing. No admin left: posting and leaving work, nothing else, as in E. Ban: remove from EV, then one purge-by-author item per channel aspect in one commit. Read-only mode: demote EV per channel, one commit each, or a client-honored flag. Rate limits: none per member in osis.

## Core features and Matrix

Nothing blocks this. Wanted: node-card opt-out per label (else 100,000-member spaces cost about 200 MB of cards per device), partial fetch, purge by author, the frontier study, the wake relay. Against Matrix spaces: membership and roles are inherited through nesting where Matrix repeats state per room; one roster, not one per room; deterministic merge. Shared with Matrix: no per-channel deny for a space member, and moderation bundles coarser than Discord's.
