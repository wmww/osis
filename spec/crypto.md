# Cryptography
> Summary: Suite 1 primitives (Ed25519 strict, XChaCha20-Poly1305, BLAKE3, hybrid X25519 + ML-KEM-768 sealed box), signature domains, the KDF, keys per actor kind, `/keys`, `/secrets` boxes and history boxes, per-role epochs, blob encryption, wraps, links, delete tokens, keyed hashes, grant blobs, algorithm agility.

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
- **Key actor** (node, recovery key): one 32-byte seed. Signing key from `kdf("sign", seed)`; KEM key pair from `kdf("kem", seed)` (64 XOF bytes for ML-KEM keygen, 32 for X25519); its X25519 half is also its claim key (spec/sync.md §2). The creation record commits to the signing public key only.
- **Link key L**: seed in the link (spec/permissions.md §9). Signing key from `kdf("sign", seed)`; creation nonce from the seed (derivation TBD); X25519 claim key (spec/sync.md §2) from `kdf("claim", seed)`; no KEM key. The link's actor K has role secrets `kdf("link K <role>", seed)` until K is first rotated. Boxes to L use the symmetric form with `kdf("link box", seed)` as its secret; K's admins hold the seed (spec/permissions.md §9).
- **Other actors**: one KEM key pair per role per epoch, `kdf("kem", role secret)`, so only holders of a role can open boxes sealed to that role. The read-role pair's X25519 half is the actor's claim key (spec/sync.md §2).
- **`/keys`**: a struct holding the current keyset only: per role `{ epoch, kem_key }` (a key actor: one entry, no epoch), plus, for an actor with role secrets, its **inbox**: label ID, servers, deposit seed (spec/sync.md §2). A role's entry is written by the node that rotates that role (spec/permissions.md §3); the inbox by an admin; a key actor's by its own key (a link key's by the sharer, which holds the seed). A key actor rotates its KEM key by a new keyset; old private keys are kept for old boxes.
- **Dedup secret** of a thing = `derive_key("osis v1 dedup", creation nonce)`.

## 4. `/secrets` and epochs
- Each role secret of an actor has an **epoch** (n, 16-byte random nonce), independent per role. A rotation of a set of roles (spec/permissions.md §3) gives each a fresh secret under epoch n+1 with a fresh nonce; the other roles keep their secret and epoch. Concurrent rotations of one role create several epochs with one n (a **fork**); nodes keep all of them. A role's **current** epochs are those no held rotation of it superseded; its **newest** is the current one with the greatest n, ties by lowest nonce.
- `/secrets` = `{ boxes: map<(member tid, role, epoch), box>, history: map<(role, epoch), history box> }`. A rotation of role r writes r's boxes at the new epoch and removes r's boxes at the epochs it supersedes (those it holds), so a concurrent rotation's boxes survive the merge; boxes of roles it does not rotate are untouched.
- A box seals one role's secret of one epoch to a member, AD = (actor tid, member tid, role, epoch). Forms (enum):
  - sealed: `{ recipient keyset epoch, suite ID, sealed box }` to the member's KEM key for that role (§3);
  - symmetric: a wrap under `kdf("box", s)`, s the member's own secret of that role (a link key: §3), used when the writer holds s.
- A key-actor member has one KEM key: a rotation or grant writes it one box, keyed (member, highest role among those written, the epoch written for that role), carrying every written role's secret with its epoch. The member takes each role's secret from its box with the newest epoch of that role.
- A grant writes the grantee's boxes for every granted role at each of that role's current epochs. A rotation writes new boxes for every current member of each rotated role, the owner included. A **re-seal** (spec/permissions.md §3) writes a current member's boxes for the current epochs of the roles it names.
- **History box** (role r, epoch e) = AEAD under `kdf("history", secret_r[e])` of every distinct earlier `secret_r` the rotator holds, forks included, written once per rotation of r.
- An epoch of role r **covers** a removal of member M, or a demotion of M below r, if it holds no box for M; it covers a removal or demotion inside a member M (a device of M, a member of an actor under M) if M's box in it names the newest keyset epoch of M for r (§3) that the node holds. A node that may rotate role r of an actor (spec/permissions.md §3) MUST NOT encrypt, wrap or seal under an epoch of r that does not cover a removal or demotion it knows of; it rotates first. The one exception is the wrap of the rotation commit itself (§5). An epoch whose rotation commit is pending or invalid (spec/commits.md §4) is never encrypted under; its secret is kept for reading.
- Each epoch names its suite ID.

## 5. Blobs and wraps
- **Blob encryption**: a fresh random 32-byte key per encryption, nonce all zero; nothing encrypts a blob under a caller-chosen key. Plaintext is Padmé-padded first. Blob = clear prefix || ciphertext (spec/sync.md §1). Blob ID = BLAKE3 of the whole blob.
- **Wrap** (per label, per blob): AEAD under `kdf("wrap", label read secret)`, nonce = first 24 bytes of the blob ID, plaintext = suite byte || blob key: 49 bytes. Deterministic. A wrap names no epoch: a reader tries the read secrets it holds, newest first. An uploader wraps under the newest read epoch it holds (§4), except that a commit rotating an actor's read secret is wrapped, under every label whose read secret derives from that actor's, under the newest read epoch it supersedes, so the members it seals to can open it. Label role keys for a server are those of the epochs its current step registers (spec/sync.md §5).
- **Grant blob** = clear prefix || Padmé-padded sealed box to the grantee's read-role KEM key; AD = (grantee tid, `"grant"`); payload = commit header and deltas. It has no blob key; its entry's wrap is filler.
- **Signal envelope**: encrypted and wrapped like a blob, signed under `"osis v1 signal"` (layout TBD).

## 6. Hashes and links
- Keyed content hashes: delta hash `kdf("delta", dedup secret, delta bytes)`; link content hash `kdf("link", dedup secret, canonical value)`.
- Unkeyed BLAKE3: tids, commit IDs, blob IDs.
- **Link**: (link content hash 32, blob ID 32, suite byte || blob key 33).

## 7. Delete tokens
- **Token secrets** of a delta, by its retention (spec/commits.md §5): `admin` and above, the admin secret of its thing; `author` and above, also the write secret of the actor directly above the author node in its chain (omitted for an imported delta, whose importer cannot derive it: its origin author purges at honest nodes by request and admins delete at blind nodes, spec/permissions.md §7); `writer`, also the write secret of its thing; `nobody`, none. A commit's token secrets are the union over its deltas; a blob carries the commitments of the deltas it holds (spec/sync.md §1, §3).
- Commit blob token: `kdf("delete token", secret, header salt)`, one per token secret. Chunk token: `kdf("delete token", secret, chunk prefix salt)`, one per token secret of the delta that created the chunk. Tokens are 32 bytes.
- **Token hash** = first 16 bytes of BLAKE3(token); the header lists them.
- **Commitment** in a blob prefix = first 16 bytes of BLAKE3(token hash || prefix salt). A server verifies a presented token by hashing twice.
- A token holder tries its epochs of the secret.

## 8. Agility
- Keys, signatures, KEM public keys and sealed boxes are enums (`signing_key`, `signature`, `kem_key`, `sealed`) with one case today. Cases are never removed; a new primitive is a new case.
- AEAD and KDF choices ride on the suite byte of wraps and links and the suite ID of a secret epoch. Suite 1 is the only suite.
- An unknown case or suite parks (spec/versioning.md §2).
- Migrating an actor to a new suite is a new epoch under that suite; old content stays under its suite.
