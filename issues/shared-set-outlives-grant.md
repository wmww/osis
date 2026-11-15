# A thing stays shared here after every grant on it ended
> Summary: spec/sync-set.md §2 Shared here: a thing joins a node's shared set by the act of granting it (to any actor but the account or a node) and leaves only on `unsync`, lost access or a destroyed thing's emptying. Revoking the grantee, the grantee's removal, or a tied grant ending with its membership (`add_with_grant`, so every tag share) leaves the thing synced at the granting node forever, though it is in no synced group and shared with no one; only `unsync` (found through `status().groups`, which does not say why a thing syncs) drops it. The account's other nodes behave otherwise for the same thing (only the writing node pins it).
> Priority: normal
> Tags: sync, engine, tess-call

Storage stays attributable (`status` lists it, `unsync` ends it), so this is no leak by Tess's rule as stated; it is a rule tied to an act rather than a state, and one that differs by which node wrote the grant.

Direction: shared here while a role this node's account granted on the thing is live for an actor other than the account or a node (the state the requirement names: "shared with no one, stays local"), judged per role commit on the thing; `unsync` then only for a thing still shared.
