# Sync tests that replay shrunk scripts
> Summary: about 35 tests in core/sync/tests/it are `holds_on(0, …)` replays of a script shrunk from a random history (one, `differential::a_pass_begun_while_quiet_waits_one_out_is_waited_out_spec_sync_status_1`, about 25 s); notes/principles.md (Never pin a seed) counts a shrunk history as a debugging aid, never the test. Each should become a hand-built fixture reaching its corner by construction, or go.
> Priority: low
> Tags: tests, sync
