# A lost sync ID waits for a source the spec does not state
> Summary: osis-sync's leave (`Left::sourced`, `Leave::pass_sourced`, status `pass_now`) keeps a sync ID whose holder went while a role commit on its thing waits for its lists until a pass ends with a caught-up source, with no `PASS_WAIT_MS` and none ending it at once. spec/sync-set.md §3 states no such wait (Release and Stopping end with no source at once; a release never waits for a peer that is not connected), so either the code is a remnant to delete or the spec lost a rule.
> Priority: normal
> Tags: sync

- Tests of the wait: osis-sync `leave::{a_loss_waiting_for_lists_waits_for_a_pass_with_a_source_spec_sync_set_3, leaving_the_closure_ends_a_wait_for_lists_spec_sync_set_3}`, `status::{a_sourced_pass_ends_only_with_a_caught_up_source, a_silent_source_holds_a_sourced_pass_no_past_pass_wait_ms}`.
- The removed spec text waited "for one more complete pass of S begun then that ends only once a source caught up" (a rotation's thing lists arriving after it give S back). With no source it never ends: an unbounded stall on an absent peer. The release principle (nothing kept because a release might be a mistake; what arrives again is fetched again) suggests deleting it.
