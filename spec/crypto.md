# Cryptography
> Summary: Suite 1 primitives (Ed25519 strict, XChaCha20-Poly1305, BLAKE3, hybrid X25519 + ML-KEM-768 sealed box), signature domains, the KDF, keys per actor kind, `/keys`, `/secrets` boxes and history boxes, per-role epochs and the covers rule, blob encryption, wraps, inbox blobs, links, delete tokens, keyed hashes, algorithm agility.

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
- **Plain thing** (no non-owner member): role secret = `kdf("thing <role>", owner's <role> secret, tid)`, with the owner's epoch for that role as its epoch (forks included). Giving a thing secrets of its own (spec/permissions.md §3) is a rotation of all three roles from those derived epochs: the history boxes carry the derived secrets, the commit wraps under the derived read epoch, `/keys` is written.
- **Key actor** (node, recovery key, link key): one 32-byte seed. Signing key from `kdf("sign", seed)`; KEM key pair from `kdf("kem", seed)` (64 XOF bytes for ML-KEM keygen, 32 for X25519); its X25519 half is also its claim key (spec/sync.md §2). Role secrets `kdf("role <role>", seed)`, never rotated: they exist so that things a key actor owns derive secrets like any plain thing. The creation record commits to the signing public key only. A link key's seed is in the link and its creation nonce derives from the seed (derivation TBD).
- **Other actors**: one KEM key pair per role per epoch, `kdf("kem", role secret)`, so only holders of a role can open boxes sealed to that role. The read-role pair's X25519 half is the actor's claim key (spec/sync.md §2).
- **`/keys`**: a struct holding the current keyset only: per role `{ epoch, kem_key }` (a key actor: one entry, no epoch), plus, for an actor other than a key actor, its **inbox** (label ID, servers; spec/sync.md §2) and **deposit seed** (32 random bytes, spec/sync.md §2). A role's entry is written by the node that rotates that role (spec/permissions.md §3); inbox and deposit seed by an admin, who SHOULD refresh the deposit seed whenever the read secret rotates; a key actor's by its own key. A key actor's keyset is fixed by its seed and never rotates: a key actor changes keys only by being replaced (a new key actor added, the old one removed).
- **Dedup secret** of a thing = `derive_key("osis v1 dedup", creation nonce)`.

## 4. `/secrets` and epochs
- Each role secret of an actor has an **epoch** (n, 16-byte random nonce), independent per role. A rotation of a set of roles (spec/permissions.md §3) gives each a fresh secret under epoch n+1 with a fresh nonce; the other roles keep their secret and epoch. Concurrent rotations of one role create several epochs with one n (a **fork**); nodes keep all of them. A role's **current** epochs are those no held rotation of it superseded; its **newest** is the current one with the greatest n, ties by lowest nonce.
- `/secrets` = `{ boxes: map<(member tid, role, epoch), box>, history: map<(role, epoch), history box> }`. A rotation of role r writes r's boxes at the new epoch and removes the boxes keyed with role r at the epochs it supersedes (those it holds), so a concurrent rotation's boxes survive the merge; boxes keyed with other roles are untouched.
- A box seals one role's secret of one epoch to a member, AD = (actor tid, member tid, role, epoch, form fields). Forms (enum):
  - sealed: `{ recipient keyset epoch (none for a key actor), suite ID, sealed box }` to the member's KEM key for that role (§3);
  - symmetric: `{ epoch of s, wrap under kdf("box", s) }`, s the member's own secret of that role, used when the writer holds s (a thing's owner; a key actor by its seed holder).
- A key-actor member has one KEM key: a rotation or grant writes it one box, keyed (member, highest role among those written, the epoch written for that role), carrying every written role's secret with its epoch. For each role a member takes the secret from the box, of any key, carrying that role's newest epoch.
- A grant writes the grantee's boxes for every granted role at each of that role's current epochs. A rotation writes new boxes for every current member of each rotated role, the owner included, with the keysets and history boxes, in one membership commit (the **rotation commit**; its boxes page, spec/crdt.md §8). A **re-seal** (spec/permissions.md §3) writes a current member's boxes for the current epochs of the roles it names.
- **History box** (role r, epoch e) = AEAD under `kdf("history", secret_r[e])` of every distinct earlier `secret_r` the rotator holds, forks included, written once per rotation of r.
- A **departure** from role r of actor A is a removal of a member M, a demotion of M below r, or M's edge passing its `until` (`until <= wall_ms` of the corrected clock at the time of encrypting). An epoch of role r **covers** a departure of M if it holds no box for M; it covers a departure inside a member M (a device of M, a member of an actor under M) if M's box in it names the newest keyset epoch of M for r (§3; the symmetric form's epoch of s) that the node holds. A node that may rotate role r of an actor (spec/permissions.md §3) MUST NOT **encrypt under** an epoch of r that does not cover a departure it knows of; it rotates first. Encrypting under an epoch means: wrapping under a label read key derived from its secret (§5), sealing or wrapping a box under its secret or a KEM key derived from it, or signing a stamp, step or open under a label key derived from it. Deriving delete tokens and reading are not encrypting under. The one exception is the wrap of the rotation commit itself (§5). An epoch whose rotation commit is pending or invalid (spec/commits.md §4) is never encrypted under; its secret is kept for reading.
- Each epoch names its suite ID.

## 5. Blobs, wraps, inbox blobs
- **Blob encryption**: a fresh random 32-byte key per encryption, nonce all zero; nothing encrypts a blob under a caller-chosen key. Plaintext is Padmé-padded first. Blob = clear prefix || ciphertext (spec/sync.md §1). Blob ID = BLAKE3 of the whole blob.
- **Wrap** (per label, per blob): AEAD under `kdf("wrap", label read secret)`, nonce = first 24 bytes of the blob ID, plaintext = suite byte || blob key: 49 bytes. Deterministic. A wrap names no epoch: a reader tries the read secrets it holds, newest first. An uploader wraps under the newest read epoch it holds (§4), except that a commit carrying boxes of a read epoch e (a rotation) is wrapped, under every label whose read secret derives from that actor's, under the newest read epoch e supersedes, so the members it seals to can open it. Label role keys for a server are those of the epochs its current step registers (spec/sync.md §5).
- **Inbox blob** (spec/sync.md §3) = clear prefix || Padmé-padded sealed box to the recipient actor's read-role KEM key, AD = (recipient tid, `"inbox"`); payload = a membership commit (header and deltas) about the recipient, plus the label IDs and server addresses of the things it names. Its prefix expiry is a delivery lifetime (`INBOX_LIFETIME`, TBD), not a commit expiry; it has no blob key and its entry's wrap is filler.
- **Signal envelope**: encrypted and wrapped like a blob, signed under `"osis v1 signal"` (layout TBD).

## 6. Hashes and links
- Keyed content hashes: delta hash `kdf("delta", dedup secret, delta bytes)`; link content hash `kdf("link", dedup secret, canonical value)`.
- Unkeyed BLAKE3: tids, commit IDs, blob IDs.
- **Link**: (link content hash 32, blob ID 32, suite byte || blob key 33).

## 7. Delete tokens
- **Token secrets** of a delta, by its retention (spec/commits.md §5), each at a **level**: `admin` and above, the admin secret of its thing (level 1); `author` and above, also the write secret of the actor directly above the author node in its chain (level 2; omitted for an imported delta, whose importer cannot derive it: its origin author purges at honest nodes by request and admins delete at blind nodes, spec/permissions.md §7); `writer`, also the write secret of its thing (level 3); `nobody`, none. A commit's token secrets are the union over its deltas; a blob carries the commitments of the deltas it holds (spec/sync.md §1, §3).
- Commit blob token: `kdf("delete token", secret, header salt)`, one per token secret. Chunk token: `kdf("delete token", secret, chunk prefix salt)`, one per token secret of the delta that created the chunk or page; for a chunk of a header list, one per token secret of the commit. Tokens are 32 bytes.
- **Token hash** = first 16 bytes of BLAKE3(token); the header lists them with their levels.
- **Commitment** in a blob prefix = level byte || first 16 bytes of BLAKE3(token hash || prefix salt). A server verifies a presented token by hashing twice and requires the signature its level calls for (spec/sync.md §5).
- A token holder tries its epochs of the secret.

## 8. Agility
- Keys, signatures, KEM public keys and sealed boxes are enums (`signing_key`, `signature`, `kem_key`, `sealed`) with one case today. Cases are never removed; a new primitive is a new case.
- AEAD and KDF choices ride on the suite byte of wraps and links and the suite ID of a secret epoch. Suite 1 is the only suite.
- An unknown case or suite parks (spec/versioning.md §2).
- Migrating an actor to a new suite is a new epoch under that suite; old content stays under its suite. A key actor migrates by being replaced (§3).
