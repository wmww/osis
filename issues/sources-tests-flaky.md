# One osis sources:: test still has a wall-clock wait on a success path
> Summary: `sources::write_in_flight_gives_up_after_connection_wait` connects under a 400 ms `connection_wait`, since the same knob is the write's give-up time, so a connect slower than that under load fails its `unwrap`. Not seen failing.
> Priority: low
> Tags: tests, osis

A separate knob for the give-up time, or a model clock for the client's wait, would remove it; neither is worth adding until it fails.
