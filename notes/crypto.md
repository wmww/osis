# Crypto: primitives, keys, wraps, epochs
> Summary: Decided 2026-10-16 (agent's call, owner deferred; the hybrid post-quantum choice is flagged for the owner). Suite 1: Ed25519 (strict) for every signature, XChaCha20-Poly1305 for every AEAD, BLAKE3 for hash, KDF and MAC, a hybrid X25519 + ML-KEM-768 sealed box for sealing role secrets to members. Key actors have a signing key committed by the tid plus a rotatable KEM key; every other actor derives one KEM key pair per role from that role's secret and publishes the public halves in `/keys`; `/secrets` holds one sealed box per (member, role) for the current epoch plus symmetric history boxes per (epoch, role). Agility: algorithm enums on every key, signature and box, a suite byte in every wrap and link, a suite id per secret epoch; unknown means parked.

## Suite 1
- **Signatures** (nodes, recovery keys, link keys, label role keys): Ed25519 (RFC 8032) with strict verification (reject non-canonical encodings and small-order points, as ed25519-dalek `verify_strict`), so every node accepts exactly the same signatures and batch verification agrees with single verification. Input is always `domain || digest`: an ASCII domain ("osis v1 commit", "osis v1 signal", "osis v1 label register", ...) then the 32-byte BLAKE3 digest of the canonical bytes. A commit is signed over its commit ID (hash of the header without the signature field).
- **AEAD** everywhere (blobs, wraps, sealed-box payloads, signal envelopes, history boxes, local units, key-tree nodes): XChaCha20-Poly1305, 32-byte key, 24-byte nonce, 16-byte tag. Random nonces are safe, pure Rust and WASM are fast enough, one AEAD to reason about.
- **Hash, KDF, MAC**: BLAKE3. `kdf(purpose, secret, input) = keyed_hash(derive_key("osis v1 " + purpose, secret), input)`; the per-purpose subkey is cacheable; XOF where more than 32 bytes are needed (KEM seeds).
- **Sealed box** (public-key encryption of secrets to a member): hybrid KEM X25519 + ML-KEM-768 (FIPS 203). `K = derive_key("osis v1 hybrid kem", ss_x || ss_m || ct_x || ct_m || pk_x || pk_m)`, rejecting a non-contributory X25519 result; box = ct_x (32) || ct_m (1088) || AEAD_K(nonce 0, AD = context, payload). Public key 1216 bytes, box overhead 1136 bytes. This is the generic hash-everything combiner (secure if either KEM is), chosen over X-Wing because X-Wing was a draft at decision time; if it is an RFC when we implement, add it as a second case instead.
- **Randomness**: OS CSPRNG. Secrets zeroized on drop.
- Not in the protocol: password hashing (an app exporting a recovery key uses Argon2id), transport crypto (TLS 1.3, QUIC, iroh, notes/networking.md).
- Crates (proposal, pure Rust): ed25519-dalek, x25519-dalek, libcrux-ml-kem (formally verified), chacha20poly1305, blake3, zeroize. The SHA3/SHAKE inside ML-KEM is internal to that primitive; "BLAKE3 is the only hash" (notes/constraints.md) means every hash osis computes itself.

## Why
- **Ed25519**: 32-byte keys, 64-byte signatures, fast verification per commit. PQ signatures rejected for v1 (ML-DSA-44: 2420-byte signatures, 1312-byte keys, more than ten times the 200-byte commit floor). Forgery is not retroactive: nodes rotate to a PQ scheme (new enum case, key actors rotate by hand-over) before a quantum attacker exists, and stored data stays valid.
- **Hybrid PQ for sealing secrets** (yes; owner may override): sealed boxes sit on blind nodes forever, and lazy rotation keeps old-epoch secrets valid for old content, so a classical-only box harvested today yields every blob under that secret, forever; a later migration cannot re-protect it. The cost lands only on membership changes, about 1.2 KB per (member, role) grant or rotation, never per blob or per commit. Per-blob wraps are symmetric and unaffected.
- **XChaCha over AES-GCM**: 96-bit GCM nonces plus frequent local unit rewrites invite nonce reuse; GCM is slow without hardware and in WASM. A hardware-speed suite can be added later for multi-GB values.

## Keys per actor kind
- **Secrets** are 32 random bytes. An actor has read, write, admin secrets per epoch (notes/permissions.md). A plain thing derives `kdf("thing <role>", owner's <role> secret, tid)`. Dedup secret = `derive_key("osis v1 dedup", creation nonce)`; the creation nonce is 32 bytes.
- **Key actor** (node, recovery key, link key L): one 32-byte seed. Signing key from `kdf("sign", seed)`, KEM key pair from `kdf("kem", seed)` (ML-KEM keygen is deterministic from 64 bytes, X25519 from 32). The creation record commits to the signing public key only; the KEM public key is signed data in `/keys`, rotatable at will (new epoch; old private keys kept for old boxes). A link seed also derives L's creation nonce, so a link URL is seed + target tid + server + K's label and L's tid is computable from it.
- **Other actors**: one KEM key pair per role per epoch, derived from that role's secret (`kdf("kem", read secret)` and so on). Members recompute them; `/keys` publishes them for granters. Per role because effective role is the minimum along the chain: a box sealed to A's write key may be opened only by A's writers; one key per actor would hand every reader of A all the write and admin secrets A holds.
- `/keys` (core aspect): map<epoch, keyset>, keyset = KEM public key per role (one for a key actor) plus the signing key for key actors, all algorithm-tagged. Membership-class write by an admin; a key actor signs its own. A granter who cannot read the grantee's thing gets the keys out of band: a contact card is a bearer link to a profile thing holding `/keys` (QR-sized; the keyset itself is about 3.6 KB), or the grantee seals to itself in the invite flow (links, notes/permissions.md).

## `/secrets` and epochs
- Epoch = version of an actor's secret set; every rotation bumps it; unrotated secrets carry over unchanged.
- `/secrets` = { boxes: map<(member tid, role), box>, history: map<(epoch, role), blob> }. box = { recipient key epoch, suite id, sealed } with AD = (actor tid, member tid, role, epoch), payload = that role's current secret. The rotating admin rewrites every current member's boxes for the rotated roles; a grant writes the grantee's boxes in the grant commit.
- History box (epoch n, role r) = AEAD under `kdf("history", secret_r[n])` of every earlier distinct secret_r, written once per rotation. Holding a role's current secret opens all its older ones (old wraps, old delete tokens); a member removed before epoch n opens nothing newer; a join costs one box per role, not one per epoch.
- Cost: grant or rotation = one sealed box (about 1.2 KB) per (member, role at or below the granted one); history = 32 bytes per earlier epoch plus a tag.
- A per-blob wrap names no epoch: a reader tries the read keys it holds, newest first, one Poly1305 check each. Blind nodes see every wrap alike (decided, was proposal in notes/sync.md).
- Each epoch names its suite id; a new AEAD or KEM is a new epoch under a new suite. Old nodes park what they cannot open (notes/versioning.md).

## Derived keys and wire objects
- **Label role keys** (notes/sync.md): Ed25519 from `kdf("label upload", read)`, `kdf("label retire", write)`, `kdf("label delete", admin)`, and `kdf("label download", read)` if download gating is adopted. Label ID: 16 random bytes stored on the group thing.
- **Blob**: fresh random 32-byte key per encryption, nonce all zero. The encrypt function generates and returns the key; nothing encrypts under a caller-supplied key, so a rewritten blob (purged delta) always gets a fresh key and ID. Plaintext is Padmé-padded before encryption; ID = unkeyed BLAKE3 of the ciphertext.
- **Wrap** (per label, per blob): key `kdf("wrap", label read secret)`, nonce = first 24 bytes of the blob ID, plaintext = suite byte || blob key (33 bytes), so a wrap is 49 bytes. Deterministic: two uploaders produce identical wraps, first upload wins. The suite byte names the blob's AEAD, since one blob sits under labels of possibly different epochs.
- **Link** (large values): (keyed content hash, blob ID, suite byte || blob key), 97 bytes.
- **Delete token**: `kdf("delete token", write secret, blob ID)`, 32 bytes; the header carries the first 16 bytes of BLAKE3(token). The author tries its epochs.
- **Keyed content hashes**: `kdf("delta", dedup secret, body)`, `kdf("link", dedup secret, value)`. Unkeyed BLAKE3 for what survives a purge (blob IDs, commit IDs over headers).
- **Signal envelope**: encrypted and wrapped like a blob, signed under "osis v1 signal".
- **Local store**: unit and key-tree keys 32 bytes, random 24-byte nonce per write. Local, changes freely.

## Agility
- Every key, signature and sealed box on the wire is an enum (`signing_key`, `signature`, `kem_key`, `sealed`) with one case today; cases are never removed, a new primitive is a new case (notes/versioning.md). AEAD and KDF choices ride on the suite byte in wraps and links and the suite id of a secret epoch. An unknown case parks: the commit stays unverified, the blob unopened, both stored and relayed.
- Migration: a new suite is a new epoch per actor (one box per member, no content re-encryption; old content stays under old suites forever) and re-signed `/keys`. PQ signatures: add the case, rotate key actors by hand-over.

## Rejected
- Node KEM keys as the only sealing target (a granter would need the grantee's device list; a new device would need re-grants from everyone).
- Tid committing to the KEM key (1.2 KB in every chain certificate; rotation would need a hand-over).
- One KEM key per actor (a reader of A could open A's write and admin boxes).
- Cleartext epoch byte in wraps (leaks rotation timing per blob to save one tag check).
- AES-256-GCM and AEGIS (above), HPKE (SHA-256 inside, no hybrid in the RFC), X-Wing (draft at decision time), ML-KEM-1024 (768 matches TLS and Signal practice), PQ signatures in v1.
