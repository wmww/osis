# Blind-node entry metadata can be spoiled by a reader who uploads first
> Summary: A blind node cannot verify a wrap, an expiry or a token commitment, so a malicious reader that reaches a server before the author can make the server's copy unreadable or short-lived; the metadata rules bound it but no mechanism closes it. Constraints tension 18; owner to accept or choose a mitigation.
> Tags: security, sync

## Problem
Everything a blind node stores beside a blob is asserted by the uploader, and every reader of a label holds the upload key, so the server cannot tell the author's upload from a reader's (found in the sync review 2026-10-16). A reader that relays a blob to a server before the author does can:
- store a garbage wrap, so readers fetching from that server cannot open the blob;
- claim a short expiry, so the server deletes the ciphertext at that time;
- store a wrong token commitment, so the author cannot hard-delete the entry by token.

This collides with "Read access never allows deleting its data or forcing a re-upload" and "Malicious readers can only waste storage" (notes/constraints.md). It needs a malicious member of the group who receives the blob by another path (P2P, another server) and wins the race to this server; in the primary pattern the author uploads its own commit first.

## What the design does (notes/sync.md, Entry metadata rules)
- Wraps: latest upload wins (rate-limited per entry); any reader whose keys open no wrap and who holds the blob key re-asserts it. A spoiled wrap is healed by the next honest sync that notices.
- Expiry: a later claim never shortens it; claims in the past are refused. A false early expiry is healed by any honest upload before it fires; after it fires, the ciphertext is gone at that server and must be re-uploaded by a holder.
- Token commitments: first upload wins; a spoiled one leaves admin hard-delete.
Residue: data that no honest node still holds is lost at that server if its wrap or expiry was spoiled first.

## Why no fix was adopted
- Server-verifiable metadata needs a signature the server can check and readers cannot forge, i.e. the soft-retire key, which the author does not hold under a label where it is only a reader (the chat pattern). Costs about 64 bytes per (label, blob) in transit and makes disappearing messages depend on chat admins.
- Hashing the metadata into the blob ID makes expiry and commitments tamper-evident but gives a reused chunk a new ID per version (O(value) entries per edit) unless chunk metadata stays mutable; wraps are per label and cannot be in the ID at all.
- Keeping several wraps per entry only moves the race (the attacker fills the slots).

## Options for the owner
1. Accept the tension as recorded (current state).
2. Writer-signed metadata where a writer uploads, provisional otherwise: closes the hole for labels the author can write to, at the byte cost above.
3. Make expiry deletion at blind nodes go through the bin for a short fixed window (hours), so a false early expiry is recoverable by a writer; weakens the unattended-delete promise by that window and does nothing for wraps.
