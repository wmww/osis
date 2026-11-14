# A pass begun in the same engine ms as a role commit's arrival counts as after it
> Summary: `passes_wanted` counts a complete pass for a want when `began >= since`, both engine ms: a pass whose Pull went out before a role commit arrived in the same ms counts as a pass after it (spec/permissions.md §3 Complete pass: it must not), so the commit's re-seals, withdraws and owed rotations may be decided on a pass that never saw what followed it.
> Priority: normal
> Tags: sync, engine

`received` (`Meta::received`, engine ms) and `pass_clock` are both ms. A strict `>` alone is wrong too (a pass begun after the arrival in the same ms would never count, and status begins the next pass at once in a World whose clock stands: it repeats without end). Fix: one strictly increasing engine sequence that both stamps role arrivals and begins passes (an in-memory counter does not survive the durable `cp/` pass records; store the pair (ms, seq) or make `received` itself a sequence), or have status begin a pass only once `pass_clock > since`, with a wake at `since + 1`. Tests meanwhile `w.advance(1)` between a commit's arrival and the pass that must follow it (core/sync/tests/it/duties.rs).
