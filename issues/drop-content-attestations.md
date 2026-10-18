# Drop third-party content attestations?
> Summary: Layer 2 (content validity after a revoke) could use only the revoker's own frontier, like layer 1 does, removing the attestation commit kind, the attestation fixpoint and the per-node receipt-time clause. Loss: writes other writers saw but the revoker did not die until re-grant.
> Tags: owner-call, permissions, security

## Today (spec/permissions.md §5.2)
A revoked actor's write is valid if any valid attestation by a witness (a writer of the thing) covers it before T_r, or the evaluating node itself witnessed it, or a compaction snapshot carries it. This needs: the attestation commit kind (header-only, its own retention and token rule), attestation validity as a least fixpoint over attestations ("an attestation by a later-revoked author", which the owner finds unintuitive), the rule that other nodes publish only if they cover something new, the backfill tiebreak between two witnesses, and a per-node receipt log whose time checkpoints decide validity until an attestation is published.

## Proposal
The revoke's embedded frontier covers content dots too: one entry per (aspect, author node) the revoker holds, the same bytes the revoker's attestation carries today. A revoked actor's write is valid iff the revoke's frontier covers it, a compaction snapshot by an authorized writer carries it, or a re-grant follows. Backfill stays (a dot below the frontier the node does not hold is a forgery; the frontier is contiguous per node). Nothing else in layer 2 remains; the receipt log is needed only for the revoker's own frontier at revoke time.

## Trade-off
- Lost: the "Carol variant" of the reference scenario (notes/permissions.md, Revocation): an edit received by another writer but never by the revoker dies until re-grant. Sync-then-revoke (§5.3) already makes that rare: only P2P-only edits that reached no blind node the revoker syncs.
- Kept: everything the owner required (author timestamps never decide; witnesses are writers; readers and blind nodes never witness).
- Gained: one commit kind, one fixpoint, one deletability rule and the node-dependent receipt clause gone; layer 1 and layer 2 become the same rule.
