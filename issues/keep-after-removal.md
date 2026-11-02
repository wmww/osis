# Option: a removed holder keeps a read-only copy of what it held
> Summary: spec/permissions.md §3 says a node that lost read access MUST drop the secrets and every unit it can no longer read, and requirements Deletion agrees. Uncooperative clients can keep it anyway. Owner: define this in core as an option, so keeping or erasing becomes a product decision for apps.
> Tags: spec, permissions, engine, node-sync

Design points, from chat design reviews (notes/chat-designs/c.md, e-review.md):
- Whose option: the removed node's local policy per group or actor is the honest fit, since no one can enforce it. Device removal (a departure on the account) must stay erase by default.
- Read: state is plaintext in the store, so no read needs the secret, and same held bodies read alike. Later purges and sender deletions no longer reach a kept copy; expiry still runs from held headers.
- `forget` also clears `syncing`, sync records and ciphertext; `deliver.rs` returns early when nothing was forgotten. So split "stop syncing" from "shred units". `compute_labels` skips a group with no read secret, so no session or `wait_synced(All)` hang. Upload filters on `may_read`. Unfetched lazy attachments become unreachable.
- Re-grant is then like a long-offline holder, not a fresh node. Re-sealing a kept commit's body on re-grant: not checked.
- Spec: permissions §3 and requirements line on Deletion.
