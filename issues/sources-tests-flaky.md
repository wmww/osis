# osis sources:: test with a wall-clock wait on a success path
> Summary: `write_in_flight_gives_up_after_connection_wait` connects under a 400 ms `connection_wait` (the same knob is the write's give-up time), so a slow connect would fail its `unwrap`; never seen failing (320 runs, 16 at a time on 2 cores, passed).
> Priority: low
> Tags: tests, osis

A separate knob for the give-up time, or a model clock for the client's wait, would remove it; neither is worth adding until it fails.
