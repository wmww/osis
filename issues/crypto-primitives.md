# Crypto primitives and key formats
> Summary: No crypto primitives or key formats chosen yet; all are permanent wire surface. Needs owner discussion before the protocol spec can be finished.
> Tags: security, sync, permissions

Everything here lands on the blob surface, which readers accept forever (notes/versioning.md), so choices are permanent and need a migration path.

## To decide
- Signatures: scheme for node keys, key actors (recovery keys, link keys L) and the three label role keys. Ed25519 is the obvious default.
- Symmetric AEAD for blobs, wraps, signal envelopes and local store units; nonce rules (wrap nonce is derived from blob ID today; blob keys are single-use).
- KDF for role-secret derivations (plain-thing secrets from owner secrets + tid, label keys, delete tokens, dedup secret from creation nonce).
- Public-key encryption for wrapping role secrets to a member actor. Gap: nodes only have signing keys today. Options: per-node encryption key (X25519, HPKE) published in `/node` or the creation record; or wrap only to a member actor's own read secret, down to nodes, which still needs node encryption keys at the bottom.
- Key epochs: how a reader finds the right epoch after rotation (proposal: try the few live keys, no cleartext epoch byte) and how `/secrets` stores every epoch.
- Crypto agility: algorithm IDs on the wire, and the "per-label epochs, old nodes blind until upgraded" path (notes/versioning.md: not designed). Includes whether to go hybrid post-quantum for key wrapping now (harvest-now-decrypt-later matters for blind-node-stored data).
- Padding (Padmé) is decided; hash is BLAKE3 (decided).

## Depends on it
plans/protocol-spec.md (header signature, wrap format, label registration), local store implementation.
