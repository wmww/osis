# Crypto: rationale
> Summary: Why suite 1 (spec/crypto.md) is what it is, costs of keys and boxes, proposed crates, rejected options. The suite was the agent's call with the owner deferring; hybrid post-quantum boxes follow from the requirement that long-lived secrets resist a future quantum attacker.

## Why
- **Ed25519**: 32-byte keys, 64-byte signatures, fast verification per commit. Strict verification so every node accepts exactly the same signatures. PQ signatures not now: ML-DSA-44 has 2420-byte signatures and 1312-byte keys, over ten times the commit floor. Forgery is not retroactive: nodes rotate to a PQ scheme (new enum case, key actors rotate by hand-over) before a quantum attacker exists, and stored data stays valid.
- **Hybrid PQ sealed boxes**: boxes sit on blind nodes forever and lazy rotation keeps old secrets valid for old content, so a classical box harvested today would yield every blob under that secret, forever; a later migration cannot re-protect it. The cost lands only on membership changes (about 1.2 KB per member and role), never per blob or commit. Generic hash-everything combiner (secure if either KEM is); X-Wing was a draft at decision time; if it is an RFC by implementation, add it as a second case.
- **XChaCha20-Poly1305 over AES-GCM**: 96-bit GCM nonces plus frequent local unit rewrites invite nonce reuse; GCM is slow without hardware and in WASM. A hardware-speed suite can be added later for multi-GB values.
- **KEM key per role** for non-key actors: effective role is the minimum along the chain, so a box sealed to A's write key must be openable only by A's writers. One KEM key per actor would hand every reader of A all of A's write and admin secrets.
- **`/keys` holds the current keyset only**: nobody seals to an old epoch on purpose, and a granter with a stale key still succeeds because members keep old secrets.
- **Link keys sign only**: K's secrets derive from the seed until K first rotates, and after that L's boxes use the symmetric form under a seed-derived secret, so L needs no KEM key and a link URL is just seed + target + server + K's label.
- **Symmetric box form** when the writer already holds the recipient's role secret (a thing's secrets to its owner): 49 bytes instead of 1.2 KB.
- **History boxes**: holding a role's current secret opens every older one; a member removed before epoch n opens nothing newer; a join costs one box per role, not one per epoch.
- **Wraps name no epoch**: a cleartext epoch byte would leak rotation timing per blob to save one tag check. A lagging relayer's older-epoch wrap extends an ex-member's reach by that blob (tension 7).
- **Blob encryption never takes a caller key**, so a rewritten blob (purged delta) always gets a fresh key and ID.
- ML-KEM's internal SHA3/SHAKE is internal to that primitive; "one hash function" means every hash osis computes itself.

## Costs
- Grant or rotation: one sealed box (about 1.2 KB) per (member, role at or below the granted one), one per device for key-actor members. History: 32 bytes per earlier epoch plus a tag. `/keys`: about 3.6 KB for three roles.
- A contact card (QR-sized) is a link to a profile thing holding `/keys`, since the keyset itself is too big for a QR code.

## Implementation
- Crates (proposal, pure Rust): ed25519-dalek, x25519-dalek, libcrux-ml-kem (formally verified), chacha20poly1305, blake3, zeroize. Secrets zeroized on drop.
- Not in the protocol: password hashing (an app exporting a recovery key uses Argon2id), transport crypto (TLS 1.3, QUIC, iroh).

## Rejected
- Per-epoch `/keys` history, per-role boxes to devices, a KEM key and box for link keys: needless 1.2 KB objects.
- Node KEM keys as the only sealing target: a granter would need the grantee's device list; a new device would need re-grants from everyone.
- Tid committing to the KEM key: 1.2 KB in every chain certificate; rotation would need a hand-over.
- One KEM key per actor (above). Cleartext epoch byte in wraps (above).
- AES-256-GCM and AEGIS (above); HPKE (SHA-256 inside, no hybrid in the RFC); X-Wing (draft at decision time); ML-KEM-1024 (768 matches TLS and Signal practice); PQ signatures now.
