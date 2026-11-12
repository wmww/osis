# osis sources:: tests with wall-clock waits on a success path
> Summary: `sources::a_move_ends_watches_of_the_group` hit its 20 s wait on `move_group(.., Local)` in two gates (load 23 and 28) (the move takes about 0.3 s; 72 runs, 24 at a time, all passed): a lost wakeup or hang in a group move, not slowness. `write_in_flight_gives_up_after_connection_wait` connects under a 400 ms `connection_wait` (the same knob is the write's give-up time), so a slow connect fails its `unwrap`; not seen failing.
> Priority: normal
> Tags: tests, osis

## a_move_ends_watches_of_the_group
Failed at sources.rs `x.move_group(x.g, GroupSource::Local).unwrap()`: `Network("the test's timeout")` (`World::move_group`, `within(W = 20 s)`). The step before it (a watch at the node, after the move to the node) passed. No repro setting: next step is to find what a move back to `Local` waits on (the node's acknowledgement, the old subscription's end) that could miss a wakeup.

## write_in_flight_gives_up_after_connection_wait
A separate knob for the give-up time, or a model clock for the client's wait, would remove it; neither is worth adding until it fails.
