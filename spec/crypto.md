# Cryptography
> Summary: Suite 1 primitives (Ed25519 strict, XChaCha20-Poly1305, BLAKE3, hybrid X25519 + ML-KEM-768 sealed box), signature domains, the KDF, keys per actor kind, `/keys`, `/secrets` boxes and history boxes, epochs, blob encryption, wraps, links, delete tokens, keyed hashes, delivery blobs, algorithm agility.

## 1. Suite 1 primitives
- **Signature**: Ed25519 (RFC 8032) with strict verification: reject non-canonical encodings and small-order points (as ed25519-dalek `verify_strict`). Batch and single verification MUST agree.
- **AEAD**: XChaCha20-Poly1305: 32-byte key, 24-byte nonce, 16-byte tag.
- **Hash, KDF, MAC**: BLAKE3. `kdf(purpose, secret, input) = keyed_hash(derive_key("osis v1 " + purpose, secret), input)`; BLAKE3 XOF output where more than 32 bytes are needed.
- **Sealed box**: hybrid KEM X25519 + ML-KEM-768 (FIPS 203). Sender: X25519 ephemeral exchange (reject a non-contributory result) giving `ss_x`, `ct_x` (the ephemeral public key); ML-KEM encapsulation giving `ss_m`, `ct_m`. `K = derive_key("osis v1 hybrid kem", ss_x || ss_m || ct_x || ct_m || pk_x || pk_m)`. Box = `ct_x (32) || ct_m (1088) || AEAD_K(nonce 0, AD, payload)`. Public key `pk_x || pk_m`, 1216 bytes.
- **Randomness**: OS CSPRNG.
- Every hash osis computes itself is BLAKE3.

## 2. Signatures
- Signed input is `domain || digest`: an ASCII domain string, then the 32-byte BLAKE3 digest of the signed canonical bytes. Domains: `"osis v1 commit"` (input digest: the commit ID), `"osis v1 signal"`, `"osis v1 label register"`, `"osis v1 label open"`, `"osis v1 upload"` (stamps, spec/sync.md §5); further domains TBD per signed object.
- Signers: node keys (commits by the node), recovery keys and link keys (commits signed as that key actor), label role keys (spec/sync.md §5).

## 3. Keys per actor kind
- **Role secrets**: 32 random bytes per role (read, write, admin) per epoch (§4).
- **Plain thing** (no non-owner member): role secret = `kdf("thing <role>", owner's <role> secret, tid)`. A thing that gets a non-owner member gets random role secrets of its own (spec/permissions.md §3).
- **Key actor** (node, recovery key): one 32-byte seed. Signing key from `kdf("sign", seed)`; KEM key pair from `kdf("kem", seed)` (64 XOF bytes for ML-KEM keygen, 32 for X25519); mailbox label keys from the seed (spec/sync.md §2). The creation record commits to the signing public key only.
- **Link key L**: seed in the link (spec/permissions.md §9). Signing key from `kdf("sign", seed)`; creation nonce from the seed (derivation TBD); mailbox label keys from the seed; no KEM key. The link's actor K has role secrets `kdf("link K <role>", seed)` until K is first rotated. Boxes to L use the symmetric form with `kdf("link box", seed)` as its secret; K's admins hold the seed (spec/permissions.md §9).
- **Other actors**: one KEM key pair per role per epoch, `kdf("kem", role secret)`, so only holders of a role can open boxes sealed to that role.
- **`/keys`**: a register holding the current keyset only: epoch plus, per role, the algorithm-tagged KEM public key (a key actor: its single KEM key), and the actor's **mailbox**: label ID, servers, deposit seed (spec/sync.md §2). Written by an admin of the actor; a key actor's is signed by its own key (a link key's by the sharer, which holds the seed). A key actor rotates its KEM key by a new keyset; old private keys are kept for old boxes.
- **Dedup secret** of a thing = `derive_key("osis v1 dedup", creation nonce)`.

## 4. `/secrets` and epochs
- An **epoch** is a version of an actor's role secrets, identified by (n, 16-byte random nonce). A rotation from epoch n creates an epoch n+1 with a fresh nonce; secrets not rotated carry over. Concurrent rotations create several epochs with one n (a **fork**); nodes keep all of them. The **newest** epoch is the greatest n, ties by lowest nonce.
- `/secrets` = `{ boxes: map<(member tid, role, epoch), box>, history: map<(epoch, role), history box> }`. A rotation writes the new epoch's boxes and removes the boxes of the epochs it supersedes (those it holds), so a concurrent rotation's boxes survive the merge.
- A box seals one role's secret of one epoch to a member, AD = (actor tid, member tid, role, epoch). Forms (enum):
  - sealed: `{ recipient keyset epoch, suite ID, sealed box }` to the member's KEM key for that role;
  - symmetric: a wrap under `kdf("box", s)`, s the member's role secret (a link key: §3), used when the writer holds s.
- A key-actor member has one KEM key: it gets one box, keyed (member, highest granted role), carrying every granted role's secret.
- A grant writes the grantee's boxes for every role at or below the granted one, for every epoch that still has boxes (those no held rotation superseded). A rotation writes new boxes for every current member of each rotated role.
- **History box** (epoch e, role r) = AEAD under `kdf("history", secret_r[e])` of every distinct earlier `secret_r` the rotator holds, forks included, written once per rotation.
- A node that may rotate a role of an actor (spec/permissions.md §3) MUST NOT encrypt, wrap or seal under an epoch of it that does not cover a removal or demotion it knows of; it rotates first. An epoch **covers** a removal of member M if it holds no box for M for the rotated roles; it covers a demotion of M to role r if it holds no box for M above r; it covers a removal below a member M (a device removal, or a removal in an actor under M) if M's box names a keyset epoch of M that covers it. A rotation by a writer leaves the admin boxes as they are; the epoch covers nothing for the admin role.
- Each epoch names its suite ID.

## 5. Blobs and wraps
- **Blob encryption**: a fresh random 32-byte key per encryption, nonce all zero; nothing encrypts a blob under a caller-chosen key. Plaintext is Padmé-padded first. Blob = clear prefix || ciphertext (spec/sync.md §1). Blob ID = BLAKE3 of the whole blob.
- **Wrap** (per label, per blob): AEAD under `kdf("wrap", label read secret)`, nonce = first 24 bytes of the blob ID, plaintext = suite byte || blob key: 49 bytes. Deterministic. A wrap names no epoch: a reader tries the read secrets it holds, newest first. An uploader wraps under the newest read epoch it holds (§4).
- **Delivery blob** = clear prefix || Padmé-padded box to the recipient: a sealed box to its read-role KEM key (a key actor: its KEM key), or the symmetric form under `kdf("link box", seed)` for a link key; AD = (recipient tid, `"delivery"`); payload = commit header and deltas. It has no blob key; its entry's wrap is filler.
- **Signal envelope**: encrypted and wrapped like a blob, signed under `"osis v1 signal"` (layout TBD).

## 6. Hashes and links
- Keyed content hashes: delta hash `kdf("delta", dedup secret, delta bytes)`; link content hash `kdf("link", dedup secret, canonical value)`.
- Unkeyed BLAKE3: tids, commit IDs, blob IDs.
- **Link**: (link content hash 32, blob ID 32, suite byte || blob key 33).

## 7. Delete tokens
- **Token secrets** of a delta, by its retention (spec/commits.md §5): `admin` and above, the admin secret of its thing; `author` and above, also the write secret of the actor directly above the author node in its chain; `writer`, also the write secret of its thing; `nobody`, none. A commit's token secrets are the union over its deltas; a blob carries the commitments of the deltas it holds (spec/sync.md §1, §3).
- Commit blob token: `kdf("delete token", secret, header salt)`, one per token secret. Chunk token: `kdf("delete token", secret, chunk prefix salt)`, one per token secret of the delta that created the chunk. Tokens are 32 bytes.
- **Token hash** = first 16 bytes of BLAKE3(token); the header lists them.
- **Commitment** in a blob prefix = first 16 bytes of BLAKE3(token hash || prefix salt). A server verifies a presented token by hashing twice.
- A token holder tries its epochs of the secret.

## 8. Agility
- Keys, signatures, KEM public keys and sealed boxes are enums (`signing_key`, `signature`, `kem_key`, `sealed`) with one case today. Cases are never removed; a new primitive is a new case.
- AEAD and KDF choices ride on the suite byte of wraps and links and the suite ID of a secret epoch. Suite 1 is the only suite.
- An unknown case or suite parks (spec/versioning.md §2).
- Migrating an actor to a new suite is a new epoch under that suite; old content stays under its suite.
