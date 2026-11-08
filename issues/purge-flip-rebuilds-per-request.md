# A requester's flip rebuilds the aspect once per purge request
> Summary: When a requester of R named purge requests on an aspect of N kept commits is removed or re-granted, the engine rebuilds the aspect about once per request (`rebuild` 7 -> 43, `rebuild: body` 31 -> 1723 for N 40 -> 400, R = N/10), so a flip costs O(R x N) bodies read instead of O(R + N). Repro: osis-node `scale::repro_purge_flip_rebuilds_once`.
> Priority: normal
> Tags: engine, retention, performance

spec/requirements.md Scale: no operation is O(history). The commits re-judged (`rejudge: a commit`) stay linear in R; the rebuilds come from `retention::rejudge_purges` dropping or restoring each request's part on its own. One rebuild per flip, after every request's verdict is known, would make it linear. A hostile admin can flip a writer's role at will, so this is also a cost an attacker controls (issues/long-aspect-cost.md, A hostile admin's flips).
