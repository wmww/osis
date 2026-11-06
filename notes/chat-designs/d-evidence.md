# Evidence for design D (forward secrecy)
> Summary: Rule citations and traces for chat design D.

**Refuted by review4:** the seed box in `secrets.0` is in the recording and is sealed to the holder's KEM key, `kdf("kem", role secret)` (spec/crypto.md §3), which the device keeps with every older read secret through history boxes; so the thief opens the box and derives every hour key. The "offline device" and "what is protected" items below are wrong for the same reason.

"Traced" = read in spec, notes or code. "Estimated" = arithmetic from cited sizes. "Not closed" = inferred, not verified.

## Why today's osis has no forward secrecy against a host recording

- Blob key random per encryption (spec/crypto.md §5 "a fresh random 32-byte key per encryption"). Traced.
- The wrap is stored at the host per entry (spec/sync.md §4 "entries (blob ID, wrap ...)") and is "AEAD under kdf("wrap", label read secret)" (spec/crypto.md §5); the label read secret derives from the group's read role secret (spec/sync.md §2). So the read secret opens every wrap of its epoch. Traced.
- History boxes: "every distinct earlier secret_r of an established epoch the rotator holds, forks included" under the new epoch's secret, "written again unchanged" by every grant or re-seal (spec/crypto.md §4). So a current member opens every earlier epoch. Traced.
- Rotation only on departures: spec/permissions.md §3; "No periodic rotation, no rotation policy (Tess)" (notes/permissions.md Keys). Traced.
- Local shredding covers only the device: "Dropping a body means destroying every local copy ... its delta nonce" (spec/commits.md §5); wraps are a unit "a lingering wrap is a key" (notes/local-store.md Units). Nothing re-derives the blob key except the host's wrap plus a read secret. Traced.
- Write and admin secrets open no wrap (only the read secret does, spec/crypto.md §5); delete keys derive from the level's secret: admin (level 1), the actor's write (2), the thing's write (3) (spec/crypto.md §7). So delete keys, stamps (write key, spec/sync.md §5) and registration (delete key = admin) survive erasing read-side chain keys. Traced.

## The content chain

- A box per holder keyed (holder, role, epoch) in `secrets.0` (spec/data-model.md §9 `box_key`); the chain seed rides as a fourth key with no history entry. The "no history box" is by construction: the history map is keyed (role, epoch) and nothing forces an entry. Not closed: whether a box with a new role value parks at old nodes (spec/versioning.md §2 unknown case parks); a new enum case is the intended way (spec/crypto.md §8 agility).
- Re-seed in every read rotation: a rotation "writes r's boxes at the new epoch" for every current holder (spec/crypto.md §4); the seed is one more box in the same commit. Cost: one sealed box, about 1.2 KB (notes/permissions.md Nesting cost). Estimated.
- Hour key derivation by hash chain: `kdf` is one-way (BLAKE3 keyed derive, spec/crypto.md §1), so key(h+1) gives nothing about key(h). Traced.
- Clock skew: a commit more than `MAX_DRIFT` (1 h) ahead is parked (spec/crdt.md §2.2); the corrected clock from handshakes (spec/sync.md §6). Hence keep the previous hour too; a clock far behind harms only that node's own writes (spec/requirements.md API line 118). Traced; the two-hour figure is MAX_DRIFT plus one period.
- Prefix: the clear prefix already carries class and expiry (spec/sync.md §1, spec/wire.md §5 field 25 class); adding the hour index is a new field. Hosts already learn arrival times (spec/requirements.md line 37 "timing"), so the hour leaks nothing new. Traced.
- Which blobs wrap under which key: projection splits a commit by retention class (spec/sync.md §3); `created.0` is `nobody` and so always its own blob (spec/commits.md §5), role commits are their own commits (§2), certificates and node cards are "a fresh encryption per label" (spec/sync.md §3). So the class split exists at upload time. Traced.

## Erasure at devices

- Kept bodies need their blob key after the hour key is gone: today the key is only in the wrap (spec/crypto.md §5). Storing it in the body's store unit is a new local rule; units are shredded with the body (notes/local-store.md Units, Shred semantics). Re-upload as a fresh encryption needs the plaintext or the key (spec/sync.md §6 "as a fresh encryption if the old blob ID is tombstoned"). Traced; the rule is new.
- Window at zero: an in-flight upload wrapped under the hour just ended, or one from a clock behind by under an hour, is unreadable. At infinity: today's behaviour. Arbitrary-values check as in notes/arbitrary-values.md.
- Offline device: it derives forward from its last state; a departure while it was offline re-seeds, and the rotation commit carrying its new box is wrapped under the read epoch it supersedes (spec/crypto.md §5 exception), which the device holds, so it opens the new seed. Traced.
- "Never received again" after a snapshot turns invalid makes a node fetch dropped bodies again (spec/permissions.md §5.2); with the hour key gone, it cannot open them. Rare; a real loss. Traced.

## Hosts and must-hold

- Timed deletes exist: "Optionally timed: the entry is removed at the given time" by a level's delete key (spec/sync.md §5); the uploader holds levels 2 and 3 for its own deltas (spec/crypto.md §7). Traced.
- Without a new rule, writers re-upload must-hold bodies the label lacks (spec/sync.md §6), which would re-expose history under the current key; hence the "older than the window is may-hold" rule. Traced by rule; new.
- Deposits are not affected (sealed to the read KEM key, spec/crypto.md §5).

## Transfer to a new device

- Bundles: a one-way log replay with entries, wraps and stamps (spec/sync.md §11, spec/wire.md §12); "An importer treats it as a peer with no cursor". A re-wrapped entry under the current hour key opens at the new device; stamps of old entries stay valid ("stamps already accepted stay valid across re-registration", spec/sync.md §5) and the importer verifies them against the path. Direct connection: pairing already carries a direct send (notes/permissions.md Implementation "one direct send"). Traced; the re-wrap step is new.

## What is unchanged

- Purge: drops bodies by header and right (spec/commits.md §5), no key needed. Expiry: hosts delete at T from the prefix (§6). Keep at most: bounds judged on state (§5). Undo: "A commit whose body was dropped cannot be undone" (§7), kept bodies suffice. Compaction snapshots are fresh encryptions by writers (spec/sync.md §7). Ephemeral and relay-only blobs are in memory and wrap under the current key (spec/sync.md §9). Re-seals and steps use role secrets (spec/permissions.md §3, spec/sync.md §2, §5). Traced.

## Alternatives

- Ratcheting the read role secret: the sync key is kdf(read secret) and "only an admin registers" a step (spec/sync.md §2); an hourly step per label per host, and certificates placed under earlier epochs become unreadable to newcomers (notes/permissions.md Certificates: counting only newest-epoch copies cost 40 KB per holder per rotation). Traced.
- Per-sender chains: a per-sender marker in the clear links one author's blobs, which nodes that cannot read the chat must not learn (spec/requirements.md line 37); without it, readers trial-decrypt against every member's chain state (N members times skipped positions). Estimated.
- Periodic re-seed: any writer may rotate read and write (spec/permissions.md §3); a re-seed alone is a smaller write (one box per holder, 1.2 KB). Tess rejected periodic rotation (notes/permissions.md Keys); offered as an option only.

## Requirements touched

- Line 61 Deletion (forward secure where the platform offers erasable storage): strengthened, no text change.
- Line 12 Decentralization "Total data may exceed what any node tracks": for chain actors, host content past the window is unreadable to anyone not already holding it. Needs a note from Tess.
- Line 125 Out of scope (removed holder keeps its copies): unchanged.
- Line 37 (nodes that cannot read): the hour index adds nothing beyond timing; a per-sender marker would.

## Costs versus C (estimated)

- Per message: a few prefix bytes; readers try at most two keys.
- Per kick, leave or lost device: +1.2 KB per remaining account (2.7 → 3.9 KB; 3.9 MB at 1000).
- Per join: +1.2 KB. Per hour per device: shredding one key and storing blob keys of kept bodies of that hour (about 100 small writes a day at 100 messages a day).
- New device: a transfer of the whole held history over a direct connection, once; new member: nothing to download beyond the member list.
