# Chat design D: C plus forward secrecy
> Summary: Parked: Tess thinks member forward secrecy is probably undesirable; review4 refuted its claim (the seed box opens under keys the device keeps); a real fix needs erasable per-device keys, MLS-sized. What survives: a newcomer boxed the current chain state cannot read older content. The text below is the design as proposed, kept for the record.

## What is different

Everything of C holds. One thing is added, the **content chain**. A *wrap* is the small record at a host holding a blob's random key, encrypted under a label key. A *rotation* is new keys sealed to each remaining holder.

## What is protected

Threat: a recording of everything the chat's hosts ever stored, plus one member's unlocked device or its keys, taken today.
- Protected: every message deleted, expired or purged more than two hours before the theft; every message the device no longer shows.
- Not protected: what the device shows; messages deleted in the last two hours; everything sent after the theft until the next membership change (a forward hash chain); a removed member's own copies (requirements line 125); authorship, since commits are signed.
Signal protects deleted messages at once and recovers from a stolen key within a round trip; D protects after two hours and recovers at the next membership change or an optional periodic re-seed.

## Why osis blocks this today

Every blob has a random key and a dropped body's local copy is shredded, but the wrap sits at the host and opens under a key derived from the actor's read secret. Read secrets rotate only on departures, and each new epoch's history box hands every earlier secret to every holder. So one current member's read secret plus a recording opens every content blob ever stored. The blocker is exactly that: wraps under role-derived keys, history boxes, rotation only on departures. Write and admin secrets open no wrap, so delete keys, stamps and registration are untouched.

## Permissions and topology

As C, plus per chat actor:

| what | where | who holds it | how it changes |
|---|---|---|---|
| chain seed | a box per holder in `secrets.0`, like a role secret, with no history box | every reader, by account | fresh in every read rotation (kick, leave, lost device); optionally periodic |
| hour key | derived: one hash step per hour since the seed | every reader, computed locally | erased two hours after its hour, after a complete sync pass |

Content blobs (messages, reactions, attachments, their compaction snapshots) are wrapped under the hour key of their upload hour, the hour index in the clear prefix. Role commits, certificates, creation records, node cards, heartbeats and inbox blobs stay under the read secret, so newcomers still verify every author.

## Common operations

- **Send and read.** As C; the wrap uses this hour's key, a few bytes of prefix more. Readers keep the current and previous hour (clock skew up to `MAX_DRIFT`).
- **Erase.** When an hour is due, a device stores the blob keys of the bodies it keeps from that hour in their own store units, then shreds the hour key. Kept messages stay readable and re-uploadable; dropped ones are gone from every recording.
- **Offline device.** Derives forward from its last state and reads everything still at the hosts. The two-hour window bounds only the thief. At zero, in-flight and skewed uploads become unreadable; at infinity there is no forward secrecy.
- **Kick, leave, lost device.** As C, plus one sealed box per remaining account (about 1.2 KB) with the fresh seed.
- **New member.** Gets the current chain state and reads from now on. An existing member may re-publish chosen history under the current hour key; it is then exposed for two hours like fresh traffic. That makes "joiners see history" a per-chat setting.
- **New device.** Pairs, then takes a bundle from an old device over a direct connection: that device's held bodies with fresh wraps under the current hour key. Bundles exist; the re-wrap and direct delivery are new.
- **Hosts.** Content older than two hours is dead weight to newcomers; the uploader attaches a timed host delete at the message's expiry, and a rule makes such old content "may hold" so members do not re-upload it.
- **Unchanged:** purge, delete keys, keep at most, expiry, undo, compaction, ephemeral and signal data, re-seals, label steps and claim sets.

## Core changes needed

1. Per-actor option "content chain": a boxed seed without history, re-seeded in every read rotation, boxed in grants and re-seals; hourly derived key; hour index in the prefix; content blobs wrapped under it.
2. Device erasure: keep blob keys of retained bodies, shred hour keys after the window.
3. Must-hold excludes content older than the window in such a label.
4. History transfer: a re-wrapped bundle over a direct connection.
5. Optional periodic re-seed by any writer.

Rejected: ratcheting the read role secret itself (changes the label's sync key hourly and needs an admin step per hour). Per-sender chains (Signal's sender keys) give per-message protection but need per-sender state at every device and either a marker that lets hosts link one author's blobs (requirements line 37) or trial decryption against every member; a later upgrade.

## Requirements and scope

Deletion line 61 becomes true against a host recording too. Decentralization line 12 ("Total data may exceed what any node tracks") weakens for such actors: history lives in devices, not hosts. Line 125 stays. It is a per-actor osis option, not chat-only: shared records, journalism, health data, any disappearing-content space whose hosts may be recorded. History for new members (re-publish) and for new devices (transfer) are settings in C and D alike.

## Sorting into Tess's categories

- **Default:** chain on for disappearing chats; two-hour window; new devices by transfer; new members no history.
- **Setting:** chain on or off at creation; re-publish history to a joiner; periodic re-seed interval.
- **Not exposed, clean for another app:** chain on permanent chats; longer windows; no transfers.
- **Incompatible:** history for joiners from hosts alone; reading content from a recording after the window; a window below `MAX_DRIFT`; recovery from a stolen key without a re-seed.
