# order-seeds-b
- `required_drops_read_alike_large` has no shrink: wrote a throwaway shrink loop over `drops_alike` (seed 198 went 30 steps to 8 in 20 s). A shared `shrink_with(check)` would save the next agent the same.
- Issue named in the brief (required-drops-seed-198.md) did not exist; had to rebuild the replay from the test source.
- Chained replays in one background shell: a later `cargo test` in the chain rebuilt with my in-progress edit, so its "pass" was not main's.
- A crdt edit rebuilds nearly everything: about 7 min per probe build at load; batch probes before touching osis-crdt.
- Review: main moved twice during the review (seed-34000 landed mid-probe); the brief's "may land first" was already true. required-drops-seed-198.md had landed on main after the worker branched, so its delete was missing.
