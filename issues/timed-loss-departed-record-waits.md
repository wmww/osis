# A timed loss waits to the bound on a peer that judges it departed
> Summary: after a loss by an `until` alone, a peer whose kept record holds the sync ID but that judges the node departed (and knows it by nothing else) never resumes that record, so the node keeps what it lost until `LOST_HEARD_WAIT_MS`.
> Priority: low
> Tags: sync, permissions

Spec/permissions.md §2 (An `until` passing) drops once each sync ID is heard out: a source plus every own commit held elsewhere by a source's report, or no peer to be waited for (spec/sync-set.md §3 Leaving). A peer whose kept record holds S counts as waited for until that record resumes or goes. A peer that judges the node departed shares nothing with it and proves nothing it would resume the record with, so with only such peers reachable (no source showing the node's writes) the node keeps the thing until `LOST_HEARD_WAIT_MS`. Not data loss: a stall to the bound. A fix needs such a peer's holding (or its closing of S) to reach the node some other way.
