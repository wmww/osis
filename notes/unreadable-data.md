# What a node learns about data it cannot read
> Summary: The full list of what a node keeping or serving a label it cannot read learns and what it must not, the padding and wrap costs, and an index of the choices elsewhere that keep the list this short (each with where its reason lives). The requirement: spec/requirements.md, Data a node cannot read. Neighbours: notes/sync.md (index), notes/serving.md (the host), notes/networking.md (transport keys).

## Learns
- One label per synced group; overlaps between labels (shared content blobs and certificate copies; inbox, list and record blobs and per-label copies share nothing). Nesting only as far as overlap shows it.
- Blob counts, padded sizes, which entries are chunk blobs, the number of delete-key commitments (zero to three, which reveals the purgeable-by class), expiry times, arrival times, deletions and pending deletion times.
- Which labels one connection opens (so: holds the current key of); client addresses.
- Which actors dial it: a reader proves its account and the key actors it holds (by their creation records, so their tids) to every key it chose to dial, a `label.0` host's included (spec/sync-opens.md §2, connection proofs), so the node links them to the labels the connection opens; a node key only between nodes of one account.
- The roster bucket of each step's claim set (and of a rotation commit, by its padded size), which claim slots were used, when, and how many steps behind the claimant was (two late nodes of one account use one slot); roughly how many key actors read the label (static entries are not points about half the time).
- Which entries were deposited and when (a grant or a reader-originated write).
- Header-only lasting blobs: one more small stamped entry with no commitments close to a deletion it already sees (notes/sync-convergence.md).
- Whether it hosts a label at all is visible to a prober with the label ID (Open's UNKNOWN_LABEL vs REFUSED; accepted).

## Does not learn
AKs, tids other than its dialers' proven actors, thing or aspect counts, authors, role grants, another account's node identities, retention bounds. What it deleted (a delete, an expiry, a timed delete, a replaced entry) it forgets: the host store shreds every removal, so a later compromise of that node, even one that also holds the label's read secret, recovers no deleted wrap (notes/serving.md; notes/local-store.md).

## Costs
- Padmé padding costs at most about 12% under 256 B, 6% up to 64 KB, 3% above; 1-4% on average.
- The wrap costs about 25% on a minimal commit, under 5% on typical edits. Chunk, tree-node, page and inbox entries carry a filler wrap (57 random bytes) that hides nothing; it can become optional for those kinds when the entry format next changes.
- Claim keys: 32 B per reader per step (notes/label-access.md).

## Choices that keep it so
- Delete-key commitments are blinded per blob, so a host cannot tell which blobs carry one author's or actor's deletes (notes/sync.md).
- Reads gated by the sync key, claims one step at a time, refused Register and Deposit learning the code alone, opens ending at a new sync key, Status without the head (notes/label-access.md).
- Claim-set padding keys are valid points; static entries are hashes until claimed (notes/label-access.md).
- The log ID is random per storage instance, so a wiped host invalidates old cursors and two hosts' logs are unrelated (notes/serving.md).
- Clients dial hosts with an ephemeral transport key per connection, each QUIC dial on its own UDP socket; a node serving others listens under its one key, its `reach.0` key (notes/networking.md, decision 5).
- Wake-up push tokens, if built, must not link labels (notes/networking.md, Proposal).
- Clients may batch uploads to blur timing (policy).
- osis-host cannot decrypt: it gets public data only and tools/policy.py keeps it from naming decrypting calls (notes/serving.md).
