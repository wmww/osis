# Option: a removed holder keeps a read-only copy of what it held
> Summary: spec/permissions.md §3 says a node that lost read access MUST drop the secrets and every unit it can no longer read, and requirements Deletion agrees. Uncooperative clients can keep it anyway. Owner: define in core which applies, so it becomes a product decision for apps; honest clients follow it.
> Tags: spec, permissions, engine, node-sync

Design points, from chat design reviews (notes/chat-designs/c.md, e-review.md):
- Whose option (owner): not the removed node's. There is one expected behaviour, set by the system and followed by honest clients: a property of the removal or of the actor removed from. A modified client can ignore it, as it can today. Candidate: a setting on the actor (keep or erase, default erase, so device removal stays erase), which also decides removals with no author (a leave, an `until` ending); a removal may carry an override. Check: the value that applies when settings change concurrently (judged on the role timeline at the removal, in any order), access lost through nesting (several paths, each with its own setting), and re-grant.
- Read: state is plaintext in the store, so no read needs the secret, and same held bodies read alike. Later purges and sender deletions no longer reach a kept copy; expiry still runs from held headers.
- `forget` also clears `syncing`, sync records and ciphertext; `deliver.rs` returns early when nothing was forgotten. So split "stop syncing" from "shred units". `compute_labels` skips a group with no read secret, so no session or `wait_synced(All)` hang. Upload filters on `may_read`. Unfetched lazy attachments become unreachable.
- Re-grant is then like a long-offline holder, not a fresh node. Re-sealing a kept commit's body on re-grant: not checked.
- Spec: permissions §3 and requirements line on Deletion.
