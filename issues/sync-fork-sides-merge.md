# Sync after main's fork-sides engine: two sync tests and the account rotation's list blob
> Summary: Merging main's fork-sides engine (sibling rotations, an account's rotation wrapped under the pre-removal D epoch, removals carried) into the rebuilt sync left two osis-sync tests failing (ignored, naming this issue) and the sync side of the new wrap rule unbuilt.
> Priority: critical
> Tags: sync, engine, tests

- `duties::a_rotation_owed_by_the_account_is_made_at_a_pass_end_spec_permissions_3`: node 0 holds a must-hold body that caught-up reader node 1 never gets at quiet (`World::unreached_must_holds`). The scenario is the fork the engine now judges by fork-sides (owed a merge by the first node asked; a sibling's removal counts only once its rotation is held).
- `keep::a_taken_inbox_blob_is_taken_once_spec_sync_inbox_2`: `inbox: take` 7 against `inbox: entry fed` 5: a write moving the reader's own account re-settles a take (a dependency the take reads moves under fork-sides' account judging: `judge_account_again`, `Devices`).
- The account rotation's wrap (spec/crypto.md §5, the account-rotation exception; notes/engine-validity-epochs.md): its list blob must go under the same D epoch as the rotation's entry (`wrap_secret(D, Some((Q, &[])))`); check the sync facade's list-blob sealing does so. `duties::sibling_removals_apart_both_hold_through_sync_spec_permissions_3` stays ignored for this.
- Engine, for Fathom: `apply::atomic::note_role_sigs` also notes the commit writing D's seeds signed as the account (`seeds_by_author`): `Core::devices_of` (only an `account.0` delta signed as the account counts) reads the commit's record, not held yet while that commit applies, so account creation was judged signed by no node and refused.
