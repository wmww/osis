# An outsider reads none of an account's writes after a node removal (osis API)
> Summary: Through the osis API after `remove_node`, an outside reader holding the account's rotation reads neither the account's earlier write nor a later one: node-sync does not get the rotation's thing lists (or the bodies they bring back) to it. The engine is right (engine test below). Sync's to build (issues/sync-rewrite.md).
> Priority: critical
> Tags: sync, tests

## Repro
`cargo test -p osis --test it a_stolen_devices_writes_stop_counting_after_its_removal_spec_permissions_5_4 -- --ignored` (core/osis/tests/it/sync.rs): Alice's laptop and phone, Bob reading Alice's group; the laptop removes the offline phone, then writes "after". Bob holds the rotation but reads nothing of the thing. Fails on main the same.

## Cause
The rotation closes the account's first epoch. Bob holds Alice's grant to him at that epoch, but no thing list naming it, so by the epoch rule (spec/permissions.md §5.5: nothing waits for a thing list; unlisted reads invalid) the grant does not count: Bob loses read, so he reads neither write. Nothing involves the devices actor: the outsider never needs D's record, the removal or D's rotation, and carried demotions play no part.

Engine side checked: `rotation::tests_signing::a_rotations_late_list_restores_the_accounts_earlier_word_at_an_outsider_spec_permissions_5_5`. The outsider holds the rotation alone (not the removal): the grant is unlisted; `hold_lists` with the rotation's list blob makes it count again and reports the earlier write in `Changed::undropped` (its body was dropped while it did not count); offered again, it reads.

## What sync must do
- Place each rotation's thing lists (`Engine::list_blob`, the things named) under the sync IDs of the things they name, beside the rotation as its chain certificate, so every reader of such a thing gets them (spec/permissions.md §5.5, Chains travel).
- Hold a list blob that arrives before its rotation until the rotation does (`ListsHeld::Awaits`).
- After `hold_lists` (or any recount), fetch again every commit in `Changed::undropped`: its body was dropped while it did not count.
