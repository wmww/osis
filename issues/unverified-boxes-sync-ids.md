# An unverified boxes payload adds sync IDs and a dial hint to a listed thing
> Summary: A boxes payload whose author's key the recipient does not hold is taken for a thing a synced closure lists with its signature unchecked (spec/sync-inbox.md §2 Taking), so anyone who knows that thing's tid and the recipient can add a sync ID of their own to its sync record and replace its dial hint; the node then holds the forger's label as that thing's and dials where it says.
> Priority: normal
> Tags: security, sync, engine

- What a forger needs: the thing's tid, the recipient account's tid and its read keyset KEM key (public). The box it sends opens to a secret of its own (an epoch names its secret, so no real epoch's), so it reads nothing and opens no real step; but `note_sync_secrets` adds the payload's sync ID (the sender's word) beside the real ones and the dial hint in place of the last.
- Cost: storage under a thing the user consented to sync, filled by the forger's label (the store caps bound it); dials to the forger's address, and the real hint lost until the next genuine payload (connection proofs keep it from impersonating anyone).
- Why the listing takes unverified: a sync-only node is sent no chain or creation records, so it often lacks the author's key; requiring a verified signature would leave a thing a sibling accepted as an invite request here.
- Fix options: the payload carries what verifying needs (the author's creation record; for an account, its epoch's rotation chain) so the listing path always verifies; or an unverified take adds the secret but no sync ID and no hint.
