# Sync: rationale
> Summary: Why spec/sync.md looks the way it does: owner goals, why blobs and labels, why certificate copies are per label, blind-node deletion reasoning and its limits, why there is no recycle bin, what a blind node learns, compaction policy defaults, rejected alternatives, open items.

## Owner goals
- Untrusted always-on nodes (backup servers) exist and sync efficiently; two briefly-online devices syncing through one is a primary case.
- They learn no AKs, tids, value or thing sizes, counts, authorship or membership. Overlap between groups synced to one server is an accepted leak; it partly reveals nesting.
- One protocol for every node; trusted and blind peers differ only in keys held.
- A blind node may be someone's only backup: read access must not allow deletion or forced re-upload; who may delete is what each delta's retention says (spec/commits.md §5).

## Why
- **One blob per commit, random key per blob**: a commit has one ID whatever groups contain it, and atomicity beats partial-fetch efficiency (tension 5). Sharing history means adding wraps, never re-encrypting.
- **Groups as sync unit**: groups are free and overlap; owner actors as the unit would force a hand-over for every separately syncable subset.
- **Label keys derive from the group's own role secrets**, never the owner's directly, or every label of one owner would carry the same role keys and identical wraps for a shared blob, linking them at the blind node.
- **Entitlement, not group membership**, decides labeling: a thing dropped into a shared folder without an edge is silently not shared, which is the intended failure. An "add to shared folder" helper writes both. The check is cached per (thing, label), invalidated by membership changes of the label actor, the thing's edges or its owner chain.
- **Convergence as the one rule**: must-hold, may-hold and must-not-hold per body; members add what is missing, token holders delete what must go, nobody touches the middle except a compactor once. Retag on join, cleanup on leave, compaction and repair after a bad deletion are all this rule. The middle class exists so a compactor's drop and a lagging member's re-upload do not ping-pong. A wrongful deletion is healed at the next member sync by a fresh encryption; tombstones only stop stale relays and bundles replaying the identical blob.
- **Projection** instead of per-delta keys wrapped per label (a wrap per delta per label plus header redaction). Every projection verifies alone since the header carries every delta hash.
- **Certificate blobs per label**: sharing one blob across labels (one wrap each) linked every label a node syncs through its node card. Cost: a few small blobs per (node, label).
- **Self-certifying label IDs**: a random ID let anyone who learned it (an ex-reader, a leaked `/label`) squat it at a fresh server under their own keys. Two admins creating a label concurrently derive the same ID.
- **Blob prefix** fixes expiry and token commitments by the blob ID, so a relaying reader cannot spoil them; before, the first or latest upload set them. Expiry is immutable: extending it would keep ciphertext meant to be gone for anyone who later obtains keys; content that must outlive it is re-encrypted. Per-blob commitments (rather than the header's token hashes) keep projections and rewrites of one commit unlinkable at the server.
- **Commit token salt in the header**: the commit's own blob ID does not exist when the header is built and changes on rewrite or projection.
- **Token plus label key** for deletion: the token proves the purge right as of the delta, the label key proves current membership. Thing-write-secret tokens need the write key, so a writer demoted to reader loses its delete power over `writer` bodies at the rotation the demotion already does. Admin- and author-level tokens need only the upload key, because a thing's admin or author is often a mere reader of the label (anyone sharing a thing into a group they only read). The owner's ideal is current write permission for every purge; honest nodes enforce exactly that (spec/permissions.md §8), servers only this approximation. Residue, accepted as small (tension 26): an ex-writer or ex-admin keeps old-epoch tokens and the upload key, so it can delete its own old `author` bodies, or old `admin` bodies, at a server until a member re-uploads them.
- **Tokens follow retention**, one secret per level: the thing's admin secret for `admin`, plus the write secret above the author node (every device of the person holds it) for `author`, plus the thing's write secret for `writer`; none for `nobody`. Without an admin-level token a thing admin who is not an admin of the label's group had no way to delete at servers. Blobs are projected by token set as well as reader set, so a `nobody` delta is never deletable through a commit-mate's token; a commit is one blob in the common case anyway. Under the shared-owner pattern `author` collapses to `writer`: the actor above the node is the shared actor. Chunks carry the same token secrets as their commit (16 bytes per chunk per secret in the header). A reused chunk must carry the thing-write-secret tokens the reusing commit needs, else it is re-encrypted; author-chain tokens need not match, so dedup across editors survives. Residue: an author's explicit purge of a value cannot delete chunks it reused from another author's version; an admin can, and honest nodes drop the keys anyway.
- **Covered means redundant under join** (spec/commits.md §5), not "inside the snapshot's frontiers": a snapshot that omits content covers nothing it omits, so a bad snapshot is harmless and anyone can re-snapshot. It also absorbs the versioning rule that a node never compacts what it could not join.
- **Tombstones** refuse the identical blob for `TOMBSTONE_LIFETIME`, so a stale relay cannot resurrect a purged body. Members never need them: they sync before they upload, and a node holding the purge strips the value from any copy that arrives later. The lifetime is a storage-versus-churn dial, not correctness: infinite is O(deletions) storage at the server; zero lets any relay or bundle from before the deletion put the ciphertext back until a member deletes it again (tension 7's residue for a reader with an old epoch, nothing more). The log covers peers whose last sync is within the log horizon; tombstones cover deletions younger than the lifetime; a peer staler than the horizon returning later than the lifetime can resurrect, and members heal it. Blob IDs are hashes of ciphertext under random keys, so a tombstone is no fingerprint.
- **Timed delete**: a relative keep-at-most is honored with nobody online because the replacing writer schedules the server-side delete when it replaces, with its snapshot in the same sync. The server learns the deadline (owner: acceptable). A relative keep-at-most therefore implies `writer`: whoever replaces must hold the token. Absolute bounds wait for a right holder (tension 25); expiry is the server-side timer for values.
- **Purge reaches snapshots**: a compactor's snapshot carries the live values of everyone's content, so purging a write must also make it value-less in snapshot bodies, like expiry, and drop those bodies; a writer re-snapshots. Snapshots are `writer` so any writer can remove the stale snapshot at servers; they are redundant by construction, so that power costs only a re-upload.
- **Retention always on the wire**: a node without the schema (generic tools, agents, blind-ish backups holding plaintext) could otherwise not honor a MUST drop, and purge requests could not be judged without the schema either. A few bytes per delta.
- **Download authorization**: open (issues/download-authorization.md).
- Rule of thumb: per-entry rights are capabilities (tokens) whose preimage is distributed client-side; label-wide rights are role keys; revocation rides on role keys. Nothing stored at the server states a reason.

## Why no recycle bin
Earlier design: writers held a soft-retire key, retired entries went to a server-side bin for a grace period, restore needed the same key, and a generation counter forced concurrent uploaders to re-tag. Dropped (owner) because the bin was not a permission boundary: a writer could already destroy irrecoverably everywhere by compacting with an empty snapshot, while members kept no bin; nothing in the design ever listed the bin or restored from it, so it was a delayed delete; a retire carried no reason, so the client rule "re-upload what still changes state" undid moderation retires; relayed retires had no replay or ordering guard. Retention per delta gives the three roles their deletion powers directly, "covered means redundant" gives the recovery the bin was for, and compaction needs no delay. Moderation is not deletion: a chat admin removes the participant from the chat group, or the app hides the message with a chat-written marker (notes/permissions.md, Patterns).

## Limits (accepted)
- A removed writer keeps deriving tokens, but tokens alone delete nothing; its power ends when the upload key is re-registered, which every removal does.
- A removed admin holds the current delete key until re-registration and can win the race at a server by re-registering keys only it knows. Remedy: a replacement label (next index, keys from the rotated admin secret the removed admin lacks), O(entries). The index keeps a replacement's keys and ID apart from the old label's, and two admins replacing concurrently derive the same ID. Hostile admins are out of scope.
- An ex-writer or ex-admin keeps old-epoch tokens and, as a reader, the upload key, so it can delete its own old `author` bodies or old `admin` bodies at servers; healed by any member's next sync. Thing-write-secret tokens need the write key, so `writer` bodies are safe.
- A malicious current writer can wipe `writer`-purgeable bodies at a blind node; write access already lets it reset them everywhere.
- Server storage under `author` retention grows with superseded bodies of authors who have not synced since the snapshot, and departed authors' bodies stay until a thing admin cleans up (a removal is the natural moment).
- Keep-at-most at servers: relative bounds are scheduled by the replacer, absolute bounds wait for a right holder (tension 25). Expiry is the only timer a blind node runs on its own.
- Relative bounds measure from the killing commit's `ts`, so a backdated kill shortens "at least D" by up to the drift cap.
- A reader who uploads first can spoil only wraps (tension 18).
- Mixed-owner labels (chat): participants upload; a participant deletes its own messages by token; chat admins hold the label delete key but cannot purge participants' messages at honest nodes, which would re-upload them.

## What a blind node learns
One label per synced group, overlaps between labels (shared content blobs; certificate and delivery blobs share nothing), blob counts, padded sizes, which entries are chunk blobs, the number of token commitments (zero to three, which reveals the purgeable-by class), expiry times, arrival times, deletions and pending deletion times, which labels one connection syncs, client addresses. Nesting only as far as overlap shows it. Not: AKs, tids, thing or aspect counts, authors, membership, which entries are projections or rewrites of one commit, retention bounds.
- Padding with Padmé costs at most about 12% under 256 B, 6% up to 64 KB, 3% above, 1–4% on average.
- Wrap overhead: about 25% on a minimal commit, under 5% on typical edits, none on chunks.

## Policy defaults (non-normative, tune freely)
- Compaction: a right holder compacts an aspect when superseded/live bodies pass a threshold, on its next write, after a randomized delay so concurrent writers do not all snapshot. A schema that wants no automatic compaction says keep at least forever.
- `TOMBSTONE_LIFETIME` 30 days.
- Through a blind relay a client cannot prioritize permission commits before decrypting, so it downloads everything and applies membership commits and attestations first.
- Clients may batch uploads to blur timing.

## Rejected
- Owner actor as sync unit (above).
- State Merkle trees over aspects or the group hierarchy: expose shape and must follow a cyclic hierarchy.
- Home closure = everything the actor owns (complete backup by default): every thing would sit under its owner's home label beside any shared label. Owner chose explicit placement (tension 16).
- Unverifiable per-entry expiry and token metadata (first/latest upload wins).
- Soft retire, recycle bin, restore and generation counter (above).
- Server-enforced keep-at-most (absolute bound in the clear prefix): the live remainder of a body may have no snapshot yet, so nodes that fetched before and after the bound would diverge for good; expiry has no such problem because the values die too. The timed delete gives the same effect for relative bounds without it.
- Leases (entries lapse unless refreshed): conflicts with immutable expiry and with a server being the only backup.
- Plain grant under the contact label: contradicts entitlement, since every card holder reads that label.

## Open
- Download authorization: issues/download-authorization.md.
- Server abuse limits and accounts: issues/server-abuse-limits.md.
- Encrypted table of contents for partial restore from blind nodes (today a subgroup needs its own label to be restorable alone).
- Upload batching; log retention horizon per node (beyond it peers fall back to range reconciliation).
