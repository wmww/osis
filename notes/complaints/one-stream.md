# one-stream complaints
> Summary: workflow notes from the Twin rule (one connection per pair after crossed first dials).

- The opens tests' `route_all` delivers without writing `Pair::log`, so an assertion on `p.log` after it passes or fails on nothing (only `Pair::run` logs). Cost a debug round.
- A per-write delivery count in the differential world repeats every 3 writes (37, 29, 29 after the first), so an n vs 10n count must use a multiple of 3 and a warm-up write; the cause is unexplained.
- The spec's own "Limit" sentence hid the doubling: every pair of the differential world kept two connections for life, each streaming everything, and no test counted connections per pair.
