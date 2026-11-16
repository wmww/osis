# Certified: a clock read
> Summary: `sync::certified`'s `authored` reads `cert_reads_in`, which reads the clock unstamped (an edge's `until` passing moves no piece).
> Priority: low
> Tags: engine, sync, performance

- `Engine::authored` reads `cert_reads_in` → `Core::may_read`, which judges the role at `Core::now()` (issues/derived-state-recomputed.md: clock-relative). A followed key reading it is not due when an edge's `until` passes, so a chain piece stays under a read thing whose actor stopped reading the thing until another read moves it. Unverified whether a tick stamps the timelines at expiry; the whole derivation reads the same clock, so the oracle test cannot see it. Wants `Core::time.until(horizon)` as `reseal_candidates` reads it, or a check that expiry moves `Read::Into`.
