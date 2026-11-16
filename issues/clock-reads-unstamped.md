# Role reads at now that bypass the memo clock
> Summary: Some role-at-now reads take the wall clock or read the clock unstamped (`Core::may_read` through `cert_reads_in` in `sync::certified`'s `authored`), so a memo over them is not due when an edge's `until` passes and can differ from a fresh read until another read moves it; every role-at-now read should go through one clock read the way `Core::role_now` and `reseal_candidates` (`Core::time.until(horizon)`) do.
> Priority: low
> Tags: engine

- Known site: `Engine::authored` reads `cert_reads_in` → `Core::may_read`, judging the role at `Core::now()`: a chain piece stays under a read thing whose actor stopped reading it until another read moves the piece. Unverified whether a tick stamps the timelines at expiry; the oracle reads the same clock, so a differential cannot see it.
- Other per-ask clock-relative reads: issues/derived-state-recomputed.md (Not memos).
- Fix: every role-at-now read through `Core::time` (`until` where the answer holds to a horizon), or a check that expiry moves `Read::Into`. Test: a memoized answer equals a fresh read just past an `until`.
