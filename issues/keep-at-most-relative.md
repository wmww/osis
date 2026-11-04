# Drop keep at most "D after replaced" for D > 0
> Summary: Tess's call (D > 0 is a nice-to-have, drop it if it adds complexity; chosen): keep at most is only "0 after replaced" (purge on replace) or an absolute time T. Removes first-death dating for at-most bounds, host deletes timed at a relative bound and the relative `AT_MOST_GRACE` cases; keep at least (relative included) stays.
> Tags: engine, node-sync, spec

Why: the per-node dating and timed drops of D > 0 sit in the arrival-order class (notes/order-study.md option 5: 3-4 of its 22 issues then); nothing first-party uses it (chat: none).
Work: spec/requirements.md Deletion ("absolute or after it is replaced" for at most becomes "absolute, or 0 after replaced"), spec/commits.md §5 (Keep at most, Dates, timed deletes, carrier-only rule, compaction snapshot bounds), spec/data-model.md `bound`; validation refuses a relative at-most other than 0; `retention/deaths.rs`, `bounds.rs`, node-sync timed deletes, order-harness generators and tests for D > 0.
Kept as is (Tess): keep at most T. Note for Tess: chat's disappearing messages use expiry (`expires`), not keep at most T; T is "old versions gone at T, the current value kept". If T's cost shows up, ask her again with that in mind.
