# keep_clients chat kick test waits real time
> Summary: `keep_clients::chat_kick_as_seen_by_the_app_spec_permissions_3` (osis) waits 200 ms of real time after the kick, then asserts the app reads its own `msg:seen.0` from the kept copy; under load it read `None` once (passes alone, 9 of 9 reruns).
> Priority: low
> Tags: tests, osis

Seen in a full `cargo test -p osis` run at load (keep_clients.rs:223, `left: None, right: Some(Str("by the app"))`, the `keep: true` round). Wait on the condition (the copy retained and holding the app's commit) instead of `sleep(200 ms)` and `settle`.
