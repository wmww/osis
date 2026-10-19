# Format changes
> Summary: Log of changes to frozen conformance vectors. A frozen file's MANIFEST line names the entry here that last set its bytes; each entry names every file it changes and why. Entries are reviewed by the toplevel.

Entry form: `## FC-<n>: <title>`, then the files changed (paths as in MANIFEST) and a one-line reason. FC-1 is the initial freeze.

## FC-1: initial freeze
- cbor/values.vec, tid/thing.vec, chunker/gear.vec: first frozen bytes after the toplevel review of spec/wire.md §3, §6 and spec/data-model.md §5 and of osis-core.

## FC-2: second freeze
- padme/padme.vec, tid/key-actor.vec, kdf/purposes.vec, keys/seed.vec, box/boxes.vec, wrap/wrap.vec, token/tokens.vec, sign/signatures.vec (osis-crypto, reproduced independently by its reviewer), schema/core.vec, chunker/tree.vec, chunker/pages.vec, blob/prefix.vec, step/steps.vec, signal/signal.vec, link/link.vec, bundle/bundle.vec, proto/reconcile.vec, proto/messages.vec: frozen after the crate reviews of wave 2 and 3. commit/headers.vec, blob/blobs.vec and inbox/inbox.vec stay provisional pending issues/token-admin-secret.md and issues/header-list-commitments.md.
