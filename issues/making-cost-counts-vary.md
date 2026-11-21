# A work count in osis `making` varies between runs
> Summary: `osis` `making::making_an_independent_thing_costs_what_it_changed_spec_sync_set_2` failed once in a full `cargo test -p osis` run (two work counters 45→71 and 55→86 between the 4- and 40-thing worlds) and passed alone and in the next full run. A scaling count must be a function of the history, not of timing: either the test lets background work (a daemon tick, a sync round, a clock) land inside the counted window, or the product does work that depends on scheduling.
> Priority: normal
> Tags: tests, engine

Seen in a cleanup branch's run on main's code (9134806b7's parent); the test is core/osis/tests/it/making.rs (`next`, `grown`). Find which counters moved and what ran in between (counted spans: `osis_base::costs`); fix the window or the product. A count test must never be retried or loosened to pass (notes/principles.md, Check scaling, not seconds).
