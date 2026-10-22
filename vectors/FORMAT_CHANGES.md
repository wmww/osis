# Format changes
> Summary: Log of changes to frozen conformance vectors. A frozen file's MANIFEST line names the entry here that last set its bytes; each entry names every file it changes and why. Entries are reviewed by the toplevel.

Entry form: `## FC-<n>: <title>`, then the files changed (paths as in MANIFEST) and a one-line reason. FC-1 is the initial freeze.

## FC-1: initial freeze
- cbor/values.vec, tid/thing.vec, chunker/gear.vec: first frozen bytes after the toplevel review of spec/wire.md §3, §6 and spec/data-model.md §5 and of osis-core.

## FC-2: second freeze
- padme/padme.vec, tid/key-actor.vec, kdf/purposes.vec, keys/seed.vec, box/boxes.vec, wrap/wrap.vec, token/tokens.vec, sign/signatures.vec (osis-crypto, reproduced independently by its reviewer), schema/core.vec, chunker/tree.vec, chunker/pages.vec, blob/prefix.vec, step/steps.vec, signal/signal.vec, link/link.vec, bundle/bundle.vec, proto/reconcile.vec, proto/messages.vec: frozen after the crate reviews of wave 2 and 3. commit/headers.vec, blob/blobs.vec and inbox/inbox.vec stay provisional pending issues/token-admin-secret.md and issues/header-list-commitments.md.

## FC-3: link flags item
- link/link.vec: `Link` takes an optional eighth item `flags` (bit 0: single use, present only with a bit set; spec/wire.md §10, spec/permissions.md §9), so a redeemer knows to remove L in its redemption; new cases for a single-use link and for refused flags.

## FC-4: tree-node lengths
- chunker/tree.vec, keys/seed.vec: a tree node carries the plaintext length under each link (`[level, [LINK+], [len+]]`, spec/wire.md §6) and its content hash covers them (`le64(level) || for each child: hash || le64(len)`, spec/crypto.md §6), so readers seek without fetching what lies before and a content hash pins the lengths; the root hashes of `tree.vec` and the `tree-ab` case of `seed.vec` (which gains `tree-lens`) change.

## FC-5: LAN announcement and member open
- sign/signatures.vec: new signature domains `"osis v1 lan announce"` (a LAN transport key bound to the dialable key, spec/sync.md §10) and `"osis v1 member open"` (open proof 3, a member node's dialable key, spec/sync.md §5, spec/wire.md §11.2); two cases added, the others unchanged.
- kdf/purposes.vec: a new kdf purpose `"lan sig"` (the keystream sealing the announcement's signature under the lan secret, window and digest, spec/sync.md §10); one case added.
- proto/messages.vec: a new Open case with proof 3 (`[3, dialable_pk, sig]`, a member node's dialable key, spec/wire.md §11.2); the others unchanged.

## FC-6: commit ID in edge keys
- schema/core.vec: the core type `edge_key` (roster `since`, tenure `since` and `until`) gains field `2 commit: blob`, the 32-byte commit ID of the write (spec/data-model.md §9, spec/permissions.md §6), so two commits of one node at one ts (one key used from two devices) are distinct ledger keys; the core schema value and hash and the `/members` and `/tenures` samples change.
