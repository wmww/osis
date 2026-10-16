# Sync
> Summary: Blobs and their clear prefix; labels, their self-certifying IDs, registration chains and role keys; which blobs go under which label (closure, entitlement, projection, certificate and delivery blobs); blind-node state and the authorization of upload, retire, restore and hard delete; the per-label log protocol with range reconciliation fallback; compaction; subscriptions and signals; transports and addresses; file bundles.

## 1. Blobs
- A **blob** is an encrypted commit (header plus unpurged deltas; spec/commits.md) or an encrypted chunk, tree node or page of a large value (spec/data-model.md §6, spec/crdt.md §8). Blind nodes cannot tell them apart except as §4 states.
- Layout: **clear prefix** || ciphertext (framing TBD). Prefix: a random 16-byte salt (fresh per encryption), optional expiry `T`, the token commitments (spec/crypto.md §7; list length capped). Ciphertext: spec/crypto.md §5, plaintext padded with Padmé (Nikitin et al., PURBs).
- **Blob ID** = BLAKE3 of prefix and ciphertext. A blob is at most `MAX_BLOB` bytes.
- One commit may travel as several blobs (projections, purge rewrites, certificate copies, concurrent re-encryptions): same header and commit ID, each with its own key, salt and ID. Every encryption of a commit computes its prefix from the header: expiry = the header's `expires`; commitments from the header's token hashes and the new salt. A chunk reused by a later commit keeps its blob and prefix, unless its expiry is earlier than the new commit's; then it is re-encrypted.

## 2. Labels
- A synced group has a **label**: the unit a blind node stores. A label has three Ed25519 role keys: **upload** `kdf("label upload", read secret)`, **soft-retire** `kdf("label retire", write secret)`, **hard-delete** `kdf("label delete", admin secret)`, from the group thing's role secrets (explicit, or derived from its owner's by tid; spec/crypto.md §3).
- **Label ID** = first 16 bytes of BLAKE3(`"osis v1 label id"` || genesis hard-delete public key).
- **Registration chain**: steps (label ID, seq, three public keys, signature under `"osis v1 label register"` by the previous step's hard-delete key; step 0 by its own). A new step is issued on every rotation of the role secrets the keys derive from.
- `/label` on the group thing: `map<label ID, { chain: list<step>, servers: list<address> }>`. Membership-class. An address is a transport URL plus the server's static public key (§10).
- **Home label**: an actor with role secrets (not a key actor) is synced as a group of itself; that label is its home label. The home closure holds the actor thing and what its `/group` lists, nothing by ownership. A link's K label is K's home label.
- A thing in no labeled group is not synced.

## 3. What goes under a label
- **Closure**: the blobs of group G are the content commits touching any thing in G's transitive closure, plus the chunk, tree-node and page blobs they reference. Each node tags commits with their things' `/groups` and retags when group membership changes.
- **Entitlement**: an uploader puts a content blob under the label of a group G iff it holds G's read secret and G's actor may read every delta in the blob. G's actor is the group thing if it has secrets of its own, else its owner.
- **Projection**: a commit whose deltas have different reader sets is uploaded as one blob per distinct readable subset, each holding the deltas that subset may read, all with the same header and commit ID.
- **Retag**: when a thing joins a group, any member adds its live blobs under the new label; when it leaves, writers retire them under the old label.
- **Certificate blobs**: chain certificates, node cards, revokes, roster snapshots, hand-over records, attestations, and `/label` commits accompanying grants (spec/permissions.md §4) go under a label as a fresh encryption per label, never as a blob shared with another label. A roster snapshot copied as a certificate is projected to the edges the chain needs and omits `/secrets` and `/label`.
- **Delivery blob**: a commit sealed to one recipient (spec/crypto.md §5), placed under a label whose other readers may not read it.
- **Grant delivery**: a grant commit goes under the target's labels and, so the grantee can find and open it, either as a certificate copy under a label the grantee already reads and whose readers may see the grant (K's label for a link; the grantee's home label when the granter reads it), or else as a delivery blob under the grantee's contact label (below). A grantee device that accepts a grant for its person actor (from a delivery blob, from K's label, or by pairing) places a certificate copy of the grant, with the `/label` commits it needed to reach the target, under the person's home label, so the person's other and future devices find it; a consumed delivery blob may then be hard-deleted from the contact label by its owner.
- **Contact label**: a person's profile thing P is a group of itself holding `/keys` and chain certificates only; a contact card is a link (spec/permissions.md §9) to P with read role. Card holders may upload to P's label.
- A receiver keeps blobs a peer placed under a label even if its own closure disagrees.

## 4. Blind-node state
Per label: the registration chain prefix it has seen; a set of **entries** (blob ID, wrap or, for chunk/tree/page blobs, a random 49-byte filler); a **recycle bin** of soft-retired entries; **tombstones** (blob ID) of hard-deleted entries; an append-only **log** of events (entries added, retires, restores, registrations) with sequence numbers; a **generation** counter bumped by every applied retire; the grace period (default 30 days, set by admins). Blob bytes are stored once per node and deleted when no label references them.

## 5. Operations and authorization
Each operation names a label and is signed with that label's current role key:
- **Register** (hard-delete key of the previous step): accept a genesis step only if its key hashes to the label ID; with seq k held, reply "have k" to an operation under newer keys and accept k+1 onward; reject an equal seq with different keys. Relayable by any node.
- **Upload** (upload key): add entries with wraps. Carries the uploader's last-seen generation; a stale generation is rejected. Refused: a blob whose prefix expiry has passed; a blob ID with a tombstone; an oversized blob. A later upload under the upload key replaces an entry's wrap (rate-limited per entry).
- **Soft retire** (soft-retire key): move named entries to the bin for the grace period; bumps the generation. Relayable.
- **Restore** (soft-retire key): move entries back from the bin.
- **Hard delete** by admin (hard-delete key), or of one entry by token: a token whose commitment is in the blob's prefix plus a signature under the label's current upload key. Removes the entry, including from the bin, and leaves a tombstone for the grace period.
- **Expiry**: at the prefix's `T` the server deletes the entry outright: no bin, no tombstone, no generation bump.
- **Download** (authorization TBD: issues/download-authorization.md), specific-blob fetch and bin listing.
- Servers cap storage per label and may rate-limit soft retires, wrap replacements and signals per label.
- **Re-registration**: a node rotating a group's role secrets (member, device removal or hand-over) issues the new chain step at once and relays it to every server in `/label`.
- **Purge at blind nodes**: hard delete by token under every label the blob sits under, by the resetting node if it holds a token, else by any node that holds one when it sees the purge.

## 6. Protocol
- Framed messages over an ordered byte stream (§10); version negotiation and message layout TBD. Every message has a fixed maximum size; every list is paged.
- **Cursor sync**: a client keeps a cursor per (peer, label) and sends: the cursor, its own new blobs inline, and the blob IDs it gained under that label from other sources since. The peer replies with its log after the cursor minus those IDs, blobs inline, and a want-list of the gained IDs it lacks, which the client then sends.
- **Range reconciliation** (fallback when a cursor is missing or invalid, or the gained list exceeds a message): range-based set reconciliation over the IDs of the live entries (Negentropy/RBSR style; details TBD).
- One connection may sync many labels; a blob under several of them crosses it once.
- On a stale-generation rejection, a client pulls the retire events, drops those blobs from its view of the label, then re-tags: a node with keys re-uploads only commits whose join still changes state; a keyless node nothing.
- A partial node repeats reconciliation until a pass changes nothing, since newly received data may grow its closure.
- Chunk, tree-node and page blobs may be fetched lazily, by local policy.

## 7. Compaction and deletion
- **Compact**: a member uploads snapshot commits (spec/commits.md §2) for the aspects it compacts, then soft-retires the blobs they supersede. A snapshot carries `/created` of each thing it covers. It does not retire commits with an expiry or chunk blobs still linked from a retained version.
- `undefined` content is dropped by compaction; `preserve` content only by explicit purge; `purge` content on reset (spec/commits.md §5).
- Two blobs of one commit with the same delta set under one label: compaction retires the one with the higher blob ID.
- Membership commits retire only as spec/permissions.md §6 allows; attestations and certificate copies retire as the commits they cover are superseded.
- A node may drop a body locally while keeping its ID in its view of the label; only a retire removes an entry. A member MUST always be able to serve current state, from bodies or a snapshot.

## 8. Subscriptions
A connection may subscribe to labels. The peer then pushes new log events (with blobs and wraps) as they arrive, in the cursor-reply format.

## 9. Signals
- A signal is an envelope (spec/crypto.md §5) published under a label with the upload key. Inside: sender node, actor, `ts`, tid, kind, optional target node, value. Sending needs write on the thing; receiving needs read; receivers verify the sender's signature and chain like a commit and drop signals whose chain they lack.
- A node receiving a signal forwards it to its other subscribers of that label and stores nothing. Clients do not re-forward. At most once, best effort, in order per sender per connection.
- A signal fires the sending node's own matching listeners. A node not named as the target drops a targeted signal.

## 10. Transport and addresses
- Sync runs over any ordered, bidirectional byte stream with confidentiality and an authenticated peer key.
- A server address is a transport URL plus the server's static public key; a client MUST check the server's key against it.
- Clients connect to servers with an ephemeral transport key per connection. A node's dialable P2P key is separate from its signing key and published only in `/reach`, together with its preferred relays. Direct addresses are never published; they are exchanged with the peer at connection time (hole punching) or found by LAN discovery.

## 11. File bundles
A bundle is a one-way log replay for a set of labels: registration chains, entries with wraps, blobs, retire lists (format TBD). An importer treats it as a peer with no cursor.
