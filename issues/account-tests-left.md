# Tests still failing after the account port
> Summary: Tests `#[ignore]`d when `Core::me` lost its node fallback. Each failed for a cause not yet found; they may be stale rigs or real bugs. Each needs a look, then the ignore removed.
> Priority: normal
> Tags: tests, engine, core

`order::held_set_decides` (quick tier): "Lists seeds ran, but held-model judged no list write above its reset". 79% of the generator's steps make no commit (`Compact` Permission 507 of 775); compare the tally with a bare-node run to see whether roles moved under accounts starve the generator, or a step now misses its aim. Its tier-2 sizes are ignored as before.

`net_records::a_matching_tag_is_answered_and_takes_the_record_spec_sync_10` and `a_removed_node_no_longer_resumes_spec_sync_10`: a hand Resume finds the record by its proven actors but no tag matches (answer `None`), so a new record is made.

`deletion::reregistration_after_rotation_spec_sync_5`: a removed account's node walks to the new step but deposits no stranded heartbeat (`stranded_secret` is held, no diagnostic).

`deposit_queue::queued_deposit_after_seed_refresh_spec_sync_5`: "walked step does not verify under its parent" and the deposit stays pending.

`fill::newest_first_after_what_judging_needs_spec_sync_6`: a role commit granting another account on a member is not fetched before the first message.
