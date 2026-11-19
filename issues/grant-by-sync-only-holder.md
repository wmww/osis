# Grant to a holder its node keeps unread
> Summary: A probe in the S2 schema review saw a grant to a holder whose node keeps the holder unread fail `Keys(NoEpoch(Sync))` at the granter; unconfirmed, not pursued.
> Priority: low
> Tags: engine

Seen once by a probe edit (not a committed test). Matters if grants by sync-only holders are meant to work: first build a test granting from a node that keeps the holder unread and see whether the refusal is the rule or a missing epoch.
