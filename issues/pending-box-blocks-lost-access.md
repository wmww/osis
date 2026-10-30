# A stranger's pending commit keeps a removed node from forgetting
> Summary: the lost-access trigger never drops an actor that any held pending membership commit boxes to this node (`pending_grants`), whoever wrote it. Pending commits are kept without a bound, so a stranger who sends one (an inbox blob, a deposit) keeps a removed device holding the actor's secrets and content indefinitely, against spec/requirements.md Deletion ("a node that lost access to data yields nothing it can no longer read").
> Tags: security, engine

Severity: medium-low (needs a later compromise of the removed device to matter).

Where: core/engine/src/rotation/mod.rs:818 `pending_grants` (any pending commit whose `/secrets` part has a box keyed to this node, a held key actor or a readable actor, decoded unverified) and :846 `lost_among`. A pending commit with an unknown author is stored as is (apply/mod.rs:292) and never expires.

Scenario: device D is removed from group G. Before or after, anyone with a deposit seed D's actors read from sends an inbox blob carrying a made-up membership commit with a `/secrets` box on G keyed to D's tid. D's lost-access trigger sees a "pending grant" reaching G and keeps G's secrets and every unit only G reads.

Fix direction: count only pending commits whose author chain is known and whose box to this node actually opened (a reading-only candidate exists from it), and only for a bounded time after receipt (e.g. `INBOX_LIFETIME`); or drop lost secrets regardless and re-learn them if the grant applies.
