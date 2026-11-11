# one-peer-3g
> Summary: Workflow notes from building 3g (the serving side for unread data).

- The brief's "`open(conn, L)` gating the store's kinds" conflicts with the build order: the Replicator pushes Upload and Register with no open until 3i, so gating them in 3g would end replication. Left to 3i (issue updated); worth checking briefs against what a later step still runs.
- Two existing tests (`shared::a_connection_with_no_record_has_no_shared_set`, `hub_loop::a_stranger_gets_no_proof`) asserted the old rule (no set for a stranger) that the design's "unread entries to every connection" replaces; rewritten to the new rule.
- Review: the hub logs a head in its own commit before node sync steps, so "judged before any PullReply" needs the judging at the step's start, not after its event; the branch's head-change test sent the change on the reader's own connection (pushes run after re-judging) and could not see it.
