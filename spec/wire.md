# Wire formats
> Summary: Byte layouts of everything that leaves a node: common encodings, format constants, creation records, commit headers and commit blobs, blob framing and padding, the chunker and chunk trees, boxes, registration steps and claim sets, inbox blobs and signal envelopes, links and recovery cards, the node-to-node protocol, bundles, decoder limits.

## 1. Conventions
- Every structure below is canonical CBOR in the profile of spec/data-model.md §5 unless it is given as a fixed byte layout. `[a, b]` is an array with exactly those positions; `Opt(X) := [] | [X]`; `X*` repeats X zero or more times, `X+` one or more. A decoder rejects any other length, a wrong major type, or an item outside its stated size.
- Inside structures (not values): a tid is a 15-byte byte string, a commit ID, blob ID, step ID or hash a 32-byte byte string, a label ID a 16-byte byte string, a time (wall ms) or `ts` an unsigned integer. A **value** (spec/data-model.md §4) embedded in a structure keeps its value encoding (tags included).
- A role in a structure is a uint: 0 read, 1 write, 2 admin. A purgeable-by class: 0 `nobody`, 1 `admin`, 2 `author`, 3 `writer`. A token level: 1, 2, 3 (spec/crypto.md §7).
- An epoch in a structure is `[n, nonce]` (uint, 16-byte byte string).
- **AD tuples**: an AEAD associated-data tuple `(a, b, ...)` written in spec/crypto.md is the canonical CBOR array of its items in the encodings of this section; layouts below give each one.
- Signed digests: a signature's digest (spec/crypto.md §2) is BLAKE3 of the canonical bytes of the array the layout names.
- Ed25519 keys and signatures in structures are raw (32 and 64 bytes) where a layout says `pk` or `sig`; where it says `signing_key` or `signature` it holds the agility enum value (§7).
