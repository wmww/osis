# Label crate: blob framing, wraps, labels and steps, claims, stamps, inbox blobs, signals, bundles
> Summary: Implement what clients and blind nodes share about blobs and labels in `osis-label`: blob clear prefix and framing, encryption to blob and blob ID, wraps, label IDs and role keys per index, registration steps (tree by prev, signatures, step IDs), claim sets with DH-derived pseudonymous keys and static entries, entry boxes, open and claim signatures, stamps, token presentation and server-side verification, inbox blobs, the signal envelope, the `/label` aspect types and the file bundle format.
> Tags: sync, crypto, security, tests

Crate: `osis-label`. Depends on: osis-core, osis-crypto, osis-commit (prefix inputs). Unblocks: server, node-sync, membership-flows, proto (message payload types), large-values.
Spec: spec/sync.md §1–§5, §9 (envelope), §11; spec/crypto.md §5–§7; spec/permissions.md §9 (link and card layouts, by protocol-spec). Notes: notes/sync.md (why stamps, deposits, claim keys, steps as a tree), notes/crypto.md. Spec trumps this plan.

## Deliverables
- Blob framing: `Prefix { salt 16, expiry?, commitments: [(level, 16 bytes)] (capped) }` canonical layout (protocol-spec item 4), `frame(prefix, plaintext, rng) -> (BlobKey, Blob)`, `BlobId`, `open(blob, key)`; filler wraps (49 random bytes) for chunk/page/inbox entries; `MAX_BLOB` check; prefix-vs-header agreement check (spec/commits.md §4: expiry and commitments match the deltas held).
- Wrap/unwrap for a label (newest read secret first; the rotation-commit exception is the caller's choice of secret).
- Labels: `LabelId` from the genesis delete public key; role keys (sync, write, delete) per index from the group's secrets, deposit key from the actor's deposit seed and the label ID; `Step { label, prev?, sync/write/delete/deposit pubkeys, step key, claim set hash, entry boxes, signature }`, `StepId`, sign (parent's delete key; genesis by its own) and verify (genesis against the label ID), path validation (tree by prev), "step without rotation" (same role keys, fresh step key).
- Claim sets: from the registered read epoch's readers (box holders, owner, plain-group owner): per reader the DH-derived Ed25519 public key, static entries for recovery and link keys, power-of-two random padding, random order, hash; client side: derive my claim key for a step from my X25519 private key(s), trying each keyset epoch held; static-entry claim.
- Entry boxes: read secret boxed to each key-actor reader (sealed or symmetric form), AD (label ID, step key).
- Signatures: open (sync or claim key over label ID, challenge, server static key), register, stamp (`"osis v1 upload"` over label ID, blob ID, wrap), `verify_stamp(head write key)`.
- Token presentation: `present(token, level)`; server verification: commitment match (hash twice with the prefix salt) and which signature the level needs (write key for level 3, sync key for 1–2).
- Inbox blob: sealed to the recipient's read KEM key with AD (tid, `"inbox"`), payload = membership commit (header + deltas) + label IDs and server addresses; prefix expiry `INBOX_LIFETIME`; filler wrap.
- Signal envelope: encrypted and wrapped like a blob, signed `"osis v1 signal"`; fields sender node, actor, ts, tid, kind, target node?, value (layout per protocol-spec).
- `/label` aspect types: `map<LabelId, { index, steps: map<StepId, Step>, servers: list<Address>, replaced }>`; `Address` = transport URL + static key (parse/print); link and recovery-card layouts (protocol-spec item 7) encode/decode.
- Bundle (§11): streaming writer/reader for registration paths, entries with wraps and stamps, blobs, deletions; the reader yields the same event stream a peer's log would (osis-proto consumes it).

## Steps
- [x] Prefix/framing/blob ID/open; wraps; MAX_BLOB; fuzz target for prefix and bundle parsers (bundle target with step 4); chunk trees and blob-backed pages.
- [x] Labels, role keys, steps, step IDs, path validation; claim sets and claim keys both sides; entry boxes.
- [x] Open/register/stamp signatures; token presentation/verification; inbox blob; signal envelope.
- [ ] `/label` types, Address, link and card formats; bundle writer/reader.
- [ ] Vectors for each object; proptests: claim set size is a power of two and hides the count below it; a claim key verifies at its step only; a stamp binds the wrap (altered wrap fails).

## Done when
server and node-sync use only this crate for label objects; vectors frozen after protocol-spec; notes/sync.md "Implementation" section lists layouts and limits. Delete this plan.

## Progress
