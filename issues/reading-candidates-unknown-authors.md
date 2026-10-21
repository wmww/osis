# Bogus pending grants can delay a new member's first reads
> Summary: Before a new member's device can check who granted it access, an insider can send many fake pending commits that claim to grant it access too; once 256 such fakes fill the device's room for unchecked keys, the genuine grant's keys wait until the grant itself applies. The member then reads only after that (no data is exposed, nothing is lost).
> Tags: security, keys, node

Repro: `apply/keys.rs` test `bogus_grant_claims_bounded_by_role_total_spec_crypto_4`.

Pending commits' boxes give reading-only candidates (spec/crypto.md §4). Authors whose `/created` the node lacks share one budget (`UNKNOWN_AUTHOR`, 64 per role), except a commit whose `/members` part grants this node or an actor it holds, whose author gets a budget of its own (`read_pending_boxes`): bogus commits that only box the node no longer crowd out a genuine grant. But the `/members` part is as unverified as the boxes (its author's chain is what is missing), so a bogus commit can claim a grant just as cheaply, and throwaway authors each get their own budget; only the role's total `MAX_READING` (256) bounds them. Deposit budgets at the servers (inbox, labels) bound how many reach the node.

Options: carry the target's `/keys` commit with every grant's inbox payload (the grantee checks candidates against the published keyset before the grant applies; a payload field, so a wire change), or tie the privileged budget to something checkable before the chain arrives (none found: the author's signing key is in its `/created`, which is what is missing).
