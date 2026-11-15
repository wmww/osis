# Each add to a group re-judges every body under it
> Summary: n things listed in one group that syncs (home here): each add re-judges about n of the group's held bodies in read's settle, each judgement reading about n/3 commit `Meta` keys, so the n-th add costs O(n^2) reads (120 adds: 23k judgements, 8 s debug). Found by tracking's dispatch test with its things listed in home.
> Priority: normal
> Tags: engine, sync, performance

Measured with `costs` on, n `create()` commits in one process, each listing the new thing in home:

| n | `read: judged` settles | per add | deps per judgement | most in one table |
|---|---|---|---|---|
| 40 | 3,404 | 85 | 49 | 14 |
| 120 | 23,168 | 193 | 74 | 40 |

The causes `Effects::count_causes` gives for `read: judged` are almost all `JMap<CommitId, Meta>` (141k moved deps at n=120, about 12 per due key): the old bodies' judgements read many commits' `Meta`, and some of those move on every add. Time in the judgement: `read_facts` (`sync_body_now`, `body_facts_now`) about two thirds, `may_log` a fifth. Not snapshots (half a snapshot per part) and not the group closure (`Closure::contains` reads one row per tid). Next step: name the `Meta` keys a judgement reads (`body_ctx`, `held_blobs`, `readable_parts`, `secret_actor` are the candidates) and which of them an add writes.

Each change should cost in proportion to what it changed: an add should judge its own body and the few it covers, not the group's whole history.
