# Tests failing since opening by entries landed
> Summary: 16 osis-sync tests and 1 osis-engine test fail on main since the entries design replaced J, ByRole, notices and Behind; the job finishing it (sheave-r13-entries) fixes or rewrites each: stores behind not moved (an ended member at a store source must stay while a Register is owed, spec/sync-opens.md §6), re-grants and public grants not read, holding decided by secrets where the closure decides, an rng-sensitive closure count.
> Priority: critical
> Tags: sync, engine, tests

Each is in tools/known_failures.txt against this issue. Causes as first traced:
- Stores never moved past an older step (the ended member closes before the store's stream shows the rotation, then nothing reopens): `again::a_head_move_after_a_restart_*`, `delete_keys::a_demoted_writers_old_keys_*`, `differential::a_removed_reader_keeps_a_thing_the_public_syncs_unread_*`, `differential::a_holder_left_out_is_re_sealed_*`, `opens::a_removal_while_away_*`, `keep::a_reader_moves_a_removed_store_it_never_showed_its_step_*`, `keep::a_reader_moves_a_store_departed_before_it_kept_s_unread_*`, likely `growth::rotations_keep_keysets_flat_*`.
- A re-grant or a public grant not read (not traced): `grants::a_reader_granted_again_*`, `differential::the_public_granted_again_*`, `differential::grantees_of_concurrent_promotions_*`, `differential::the_publics_read_through_a_holder_*`, `flows::a_raced_grant_is_resealed_*`, `keep::a_grant_from_outside_reaches_an_account_that_removed_a_node`.
- Kept unread by a sync secret where the closure holds a stub: `differential::a_signal_only_a_removed_node_took_is_lost_*`.
- Not traced: `destruction::a_node_away_past_the_floor_learns_the_destruction_*`.
- osis-engine `closure::a_take_up_costs_what_the_opener_opens_*`: its n/10n count moves with the rng stream (39 against 42 edges).
