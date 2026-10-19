# A grant carries no history boxes: the grantee cannot read what came before it
> Summary: spec/crypto.md §4: "a grant or re-seal boxing e writes [the history box] again unchanged, so its recipient reads content under older epochs". osis-keys' `box_member` re-writes them, but the grant commit's `/secrets` delta (flows' `grant_in` via `put_secrets`) does not carry them (an unchanged value makes no write), so a grantee reached by inbox holds only the newest epoch: everything placed before the grant (content, the granter's certificates, the own-secrets rotation) stays unreadable and the grant pends on missing chain certificates.
> Tags: permissions, crypto, sync

- Seen in crates/osis-node/tests/sync_more.rs `grant_by_inbox_end_to_end_spec_sync_3` (passes because the group's content and certificates are placed after the grant; with content first, the grant stays pending `MissingChain`).
- Fix (membership-flows): make the grant's `/secrets` delta carry the history boxes of the epochs it boxes (a write that survives the diff, e.g. remove + put, or include them in the inbox payload's commit parts), and test a grantee reading pre-grant content.
