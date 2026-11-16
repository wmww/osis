# keel-sync-rest
- `again::a_delete_seen_before_a_restart_is_logged_again_once_after` was listed as failing but passed on the claimed base; the brief's count (11) was off by one.
- A test probe that calls `Engine::snapshot` before its assertion makes the test pass on its own: the first green run of `deletes::a_writer_deletes_only_what_it_may_purge` was the probe's doing. Restore the test file before judging a fix.
- The box ran at load 26 on 16 cores: the sync binary's wall time swung 23-63 s between identical runs, so wall time said nothing about the cost of a change.
- `cargo test -p X --test it a:: b::` refuses two filters; they go after `--`.
