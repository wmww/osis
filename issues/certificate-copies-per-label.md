# Certificate copies are sealed again for every sync ID
> Summary: spec/sync.md §3 seals each certificate copy (an account's `keys.0` commits, rotations, header-only mintings, key-actor cards, revoke and grant chains) fresh for every sync ID and never shares it, to avoid linking sync IDs. The linkage is already visible: commit blobs are shared across sync IDs, and dialers prove their account. An account in k groups seals, uploads and stores k copies (a `keys.0` copy is about 1.5 KB). Seal a copy once per (commit, parts) and add one wrap per sync ID.
> Priority: normal
> Tags: sync, crypto, performance

## What is wrong
The "never shared" rule exists so that one blob would not link every sync ID a node syncs through its node card. Node cards now go under D's home only (spec/permissions.md §4), so that reason no longer holds. What a shared copy would link is "account X acts in both sync IDs", which account proofs (spec/sync.md §10) and shared commit blobs (notes/whole-commits.md) already show to any node keeping both.

## Direction
A certificate copy's section opens with the blob key, not the sync ID group's read secret (`Engine::seal_to`). The per-sync-ID wrap already gates who reads it. Copies with the same parts are then one blob under every sync ID that needs them, so a node keeping several stores it once (and, with 3h2's "No bytes it holds", receives the bytes once). Copies whose parts differ per sync ID (chain-edge sets) stay separate. Header-only copies need no format change, only dropping the rule. Tests count copies sealed, uploaded and stored for an account in 1 and 10 groups.

Also correct the notes that justify designs by hidden linkage, keeping the designs: notes/sync.md (label keys from the group's own secrets: still needed for distinct IDs and keys and for a group with secrets of its own, not for unlinkable wraps; the deposit key the same), notes/unreadable-data.md ("projections or rewrites of one commit": a Replace names the entry it replaces).

## Not this
Filler wraps (57 random bytes per chunk, tree-node, page and inbox entry) hide nothing either. Make the wrap optional for those kinds only alongside other wire work (net-one-peer 3h2 changes `entry`). Per-sync-ID copies of other kinds, list and record blobs, per-thing dedup secrets, salts and blinded commitments protect content or which things, and stay.
