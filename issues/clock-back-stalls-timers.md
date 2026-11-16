# A wall clock gone back stalls sync's timers by the jump
> Summary: osis-sync keeps every deadline in wall ms (`now + wait`); after the wall clock goes back by D, a deadline set before waits D more. Proven for redial: two nodes partitioned, both clocks back an hour, healed: neither dials the other for an hour (`driver::repro_a_clock_gone_back_delays_no_redial_spec_sync_opens_1`, ignored).
> Priority: normal
> Tags: sync

- Where: `Dials::schedule` (core/sync/src/driver/dials.rs) waits for `c.last + REDIAL_MS`, `c.last` taken before the jump. The same shape is likely in the session's ping and stall deadlines and dial timeout (session.rs `track`), the store-failure retry (`driver::Stretch::retry_at`) and module back-offs; each needs its own check once the rule is in.
- The harness models it as the product does: `World::skew` keeps a node's wake at the same time of its own.
- Fix shape: one rule for every wait, not a patch per timer: a deadline more than its wait past now (the clock went back) counts as due now plus its wait (or as due), checked where deadlines are read. Spec: a sentence in spec/sync-opens.md §1 (or spec/sync-streams.md's clock section) that waits are measured on a clock that does not go back, or are cut to their length when it does.
- What a user sees: a laptop whose clock was corrected backwards stays offline for the size of the correction.
