# Certified: a whole read and a clock read
> Summary: `sync::certified` derives the read things from the whole sync set, and `authored`'s `reads_in` reads the clock unstamped (an edge's `until` passing moves no piece).
> Priority: low
> Tags: engine, sync, performance

- `Engine::read_things` derives the read things from `sync_set()` whole: one O(things) set diff per change of the sync set (every thing made). Per sync ID entries would make it per change.
- `Engine::authored` reads `reads_in` → `Core::may_read`, which judges the role at `Core::now()` (issues/derived-state-recomputed.md: clock-relative). A followed key reading it is not due when an edge's `until` passes, so a chain piece stays under a read thing whose actor stopped reading the thing until another read moves it. Unverified whether a tick stamps the timelines at expiry; the whole derivation reads the same clock, so the oracle test cannot see it. Wants `Core::time.until(horizon)` as `reseal_candidates` reads it, or a check that expiry moves `Read::Into`.
