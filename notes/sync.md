# Sync: rationale
> Summary: Why spec/sync.md looks the way it does: owner goals, why blobs and labels, why certificate copies are per label, blind-node authorization reasoning and its limits, what a blind node learns, compaction policy defaults, rejected alternatives, open items.

## Owner goals
- Untrusted always-on nodes (backup servers) exist and sync efficiently; two briefly-online devices syncing through one is a primary case.
- They learn no AKs, tids, value or thing sizes, counts, authorship or membership. Overlap between groups synced to one server is an accepted leak; it partly reveals nesting.
- One protocol for every node; trusted and blind peers differ only in keys held.
- A blind node may be someone's only backup: read access must not allow deletion or forced re-upload, and write access should not casually wipe a group.

## Why
- **One blob per commit, random key per blob**: a commit has one ID whatever groups contain it, and atomicity beats partial-fetch efficiency (tension 5). Sharing history means adding wraps, never re-encrypting.
- **Groups as sync unit**: groups are free and overlap; owner actors as the unit would force a hand-over for every separately syncable subset.
- **Label keys derive from the group's own role secrets**, never the owner's directly, or every label of one owner would carry the same role keys and identical wraps for a shared blob, linking them at the blind node.
- **Entitlement, not group membership**, decides labeling: a thing dropped into a shared folder without an edge is silently not shared, which is the intended failure. An "add to shared folder" helper writes both. The check is cached per (thing, label), invalidated by membership changes of the label actor, the thing's edges or its owner chain.
- **Retag**: any member adds eagerly (upload is a reader right); only writers retire, so stale entries leave at the old label's next compaction. Harmless meanwhile: the old label's readers already held them.
- **Projection** instead of per-delta keys wrapped per label (a wrap per delta per label plus header redaction). Every projection verifies alone since the header carries every delta hash.
- **Certificate blobs per label**: sharing one blob across labels (one wrap each) linked every label a node syncs through its node card. Cost: a few small blobs per (node, label).
- **Self-certifying label IDs**: a random ID let anyone who learned it (an ex-reader, a leaked `/label`) squat it at a fresh server under their own keys. Two admins creating a label concurrently derive the same ID.
- **Blob prefix** fixes expiry and token commitments by the blob ID, so a relaying reader cannot spoil them; before, the first or latest upload set them. Expiry is immutable: extending it would keep ciphertext meant to be gone for anyone who later obtains keys; content that must outlive it is re-encrypted. Per-blob commitments (rather than the header's token hashes) keep projections and rewrites of one commit unlinkable at the server.
- **Commit token salt in the header**: the commit's own blob ID does not exist when the header is built and changes on rewrite or projection.
- **Token plus upload key** for hard delete: the token proves authorship or write on the thing; the upload key proves current membership. With the soft-retire key instead, a chat participant (a reader of the chat label) could never finish the purge of its own message there.
- **Writer-derived tokens for `purge`-class deltas**: any current writer of such a thing finishes another writer's reset at once, and a commit may span owners and reader sets regardless of class.
- **Hard-delete tombstones** refuse re-upload for the grace period, so a purge needs no generation bump and a stale peer cannot resurrect a purged body. Blob IDs are hashes of ciphertext under random keys, so a tombstone is no fingerprint.
- **Generation as a counter** per (node, label) rather than a tag per entry.
- **Download gated by the upload key** (proposal): both derive from the read secret, a separate key gains nothing. Keyless nodes then never pull: replication between two servers is driven by a key holder, or an admin gives the mirror the upload private key alone.
- Scope of a writer's soft retire is the whole label, since the blind node sees no finer structure; history there is recoverable only for the grace period.
- Rule of thumb: per-entry rights are capabilities whose preimage is distributed client-side; label-wide rights are role keys; revocation rides on role keys. Nothing stored at the server states a reason.

## Limits (accepted)
- A removed writer keeps deriving tokens, but tokens alone delete nothing; its power ends when the upload key is re-registered, which every removal does.
- A removed admin holds the current hard-delete key until re-registration and can win the race at a server by re-registering keys only it knows. Remedy: a new label under fresh keys, O(entries). Hostile admins are out of scope.
- A writer demoted to reader keeps its old write secrets and can hard-delete `purge`-class entries of those epochs under labels it still reads: vandalism of server copies, healed by a re-snapshot.
- A malicious current writer can wipe current `purge`-class bodies at a blind node; write access already lets it reset them everywhere.
- A reader who uploads first can spoil only wraps (tension 18).
- Mixed-owner labels (chat): participants upload but cannot retire; chat admins soft-retire everyone's messages; a participant hard-deletes its own by token. Each participant's own label keeps their copies safe.

## What a blind node learns
One label per synced group, overlaps between labels (shared content blobs; certificate and delivery blobs share nothing), blob counts, padded sizes, which entries are chunk blobs, the number of token commitments (usually one), expiry times, arrival times, generations and retires, which labels one connection syncs, client addresses. Nesting only as far as overlap shows it. Not: AKs, tids, thing or aspect counts, authors, membership, which entries are projections or rewrites of one commit.
- Padding with Padmé costs at most about 12% under 256 B, 6% up to 64 KB, 3% above, 1–4% on average.
- Wrap overhead: about 25% on a minimal commit, under 5% on typical edits, none on chunks.

## Policy defaults (non-normative, tune freely)
- Compaction of `undefined` content: a writer compacts a label when superseded/live bodies pass a threshold, on its next write, after a randomized delay so concurrent writers do not all snapshot.
- Grace period default 30 days.
- Through a blind relay a client cannot prioritize permission commits before decrypting, so it downloads everything and applies membership commits and attestations first.
- Clients may batch uploads to blur timing.

## Rejected
- Owner actor as sync unit (above).
- State Merkle trees over aspects or the group hierarchy: expose shape and must follow a cyclic hierarchy.
- Home closure = everything the actor owns (complete backup by default): every thing would sit under its owner's home label beside any shared label. Owner chose explicit placement (tension 16).
- Unverifiable per-entry expiry and token metadata (first/latest upload wins).
- Hard delete by token plus soft-retire key (above).
- Plain grant under the contact label: contradicts entitlement, since every card holder reads that label.

## Open
- Download authorization and its bootstrap: issues/download-authorization.md.
- Server abuse limits and accounts: issues/server-abuse-limits.md.
- Encrypted table of contents for partial restore from blind nodes (today a subgroup needs its own label to be restorable alone).
- Upload batching; log retention horizon per node (beyond it peers fall back to range reconciliation).
