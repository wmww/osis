# Crypto crate
> Summary: Implement spec/crypto.md as `osis-crypto`: suite 1 primitives behind our own types, `kdf`, signatures with domains, the hybrid sealed box, key derivations for every actor kind, box forms, history boxes, blob encryption with Padmé padding, wraps, label role and claim keys, delete tokens and commitments, agility enums. Pure functions, injected randomness, zeroized secrets, known-answer vectors.
> Tags: crypto, security, tests

Crate: `osis-crypto`. Depends on: osis-core. Unblocks: store (AEAD), label, keys, commit, everything above.
Spec: spec/crypto.md (all), spec/sync.md §2 (label keys, claim keys, static entries), spec/data-model.md §7. Notes: notes/crypto.md (crate choices, rejected options). Spec trumps this plan.

## Deliverables
- Primitives module: Ed25519 sign/verify_strict (batch and single must agree: test), XChaCha20-Poly1305 AEAD, BLAKE3 hash/keyed/derive_key/XOF, X25519 with the non-contributory (all-zero) rejection, ML-KEM-768 with **deterministic keygen from 64 seed bytes** (required by §3; pick libcrux-ml-kem or ml-kem on that criterion and record it in notes/architecture.md), OS CSPRNG via `rand_core::CryptoRngCore` passed in by callers.
- `kdf(purpose, secret, input)` = keyed_hash(derive_key("osis v1 " + purpose, secret), input), XOF variant; every purpose string used anywhere in the spec as a `const` in one module (`"thing <role>"`, `"sign"`, `"kem"`, `"role <role>"`, `"box"`, `"history"`, `"wrap"`, `"delta"`, `"link"`, `"delete token"`, `"label sync|write|delete|deposit"`, `"label claim"`, `"lan tag"`, `"osis v1 dedup"`, `"osis v1 hybrid kem"`, `"osis v1 label id"`, `"osis v1 static claim"`), with a test that they are distinct.
- Signatures over `domain || digest` with the domain constants (`"osis v1 commit"`, `signal`, `label register`, `label open`, `upload`; further domains as plans/protocol-spec.md fixes them); a test that a signature verifies under its own domain only.
- Hybrid sealed box exactly as §1: seal(pk_x||pk_m, AD, payload, rng) → ct_x||ct_m||AEAD; open. Public key 1216 bytes. KAT with fixed randomness.
- Key actor keys from a 32-byte seed (§3): signing key, KEM pair, role secrets `kdf("role <role>", seed)`; claim key = X25519 half. Non-key actors: KEM pair per role per epoch from the role secret. Plain-thing derived secrets `kdf("thing <role>", owner secret, tid)`. Dedup secret from the creation nonce.
- Box forms (§4): sealed `{recipient keyset epoch, suite ID, sealed box}` and symmetric `{epoch of s, wrap under kdf("box", s)}`, AD = (actor tid, member tid, role, epoch, form fields); history box under `kdf("history", secret)`; encode/decode of the enum forms per the layouts plans/protocol-spec.md fixes (provisional until then, behind one module).
- Blob encryption (§5): fresh random key, zero nonce, Padmé padding (with the length-recovery rule plans/protocol-spec.md item 4 fixes; until then a provisional `le32 len || data || zeros` behind one function), blob = clear prefix || ciphertext, blob ID = BLAKE3(whole). Prefix layout itself is osis-label's; this crate exposes `encrypt_body(prefix_bytes, plaintext, rng) -> (key, blob_bytes)` and `decrypt_body`.
- Wrap/unwrap: AEAD under `kdf("wrap", read secret)`, nonce = blob ID[..24], plaintext suite byte || key (49 bytes); deterministic (test).
- Label role keys (sync/write/delete from the group's role secrets and `le64(index)`), deposit key from the deposit seed, label ID from the genesis delete public key, claim key derivation `kdf("label claim", DH(step priv, M pub), label ID || step key)` → Ed25519 seed, static entry hash, open-signature helper over (label ID, challenge, server static key).
- Delete tokens (§7): token from secret and salt, token hash (16 bytes), commitment (level byte || BLAKE3(token hash || prefix salt)[..16]), `verify_presented_token(token, commitment, salt)`.
- Agility enums `SigningKey`, `Signature`, `KemKey`, `Sealed`, suite byte/ID with one case; unknown case decodes to `Parked`.
- All secrets in zeroizing newtypes (`Secret32`, seeds, private keys); `Debug` never prints them.

## Steps
- [ ] Primitives + kdf + domains, KATs from the primitive crates' vectors.
- [ ] Hybrid box, key derivations, box forms, history boxes.
- [ ] Blob encrypt/decrypt, padding, wraps, tokens, label and claim keys.
- [ ] Vectors: every derivation and box with fixed randomness, written to vectors/ (plans/test-infra.md format; provisional until protocol-spec freezes layouts).
- [ ] Benchmarks: box seal/open, blob encrypt per MB, Ed25519 verify (criterion, not gated).

## Tests
Round trips, KATs, domain distinctness, non-contributory DH rejected, strict Ed25519 rejects non-canonical points, padding hides length classes (Padmé bucket property), wrap determinism, a token verifies only against its own commitment and salt, `Debug` of secrets redacted, no panic on malformed boxes/blobs (proptest over mutations).

## Done when
Every function spec/crypto.md names exists with a test citing its section; KATs frozen in vectors/ once plans/protocol-spec.md fixes layouts; notes/crypto.md "Implementation" section updated with the crates chosen. Then delete this plan.

## Progress
