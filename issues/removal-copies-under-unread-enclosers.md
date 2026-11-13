# Removal and deposit copies go under groups that enclose the holder unread
> Summary: `Delivery::Removal` and `Delivery::Deposit` place under every group whose closure holds the thing (`groups_holding`), also one whose actor does not read it (a team or subgroup listed in it). That group's readers then learn the thing's edge writes (who left which roster) though nothing of the thing is theirs. `Delivery::First` already skips such groups.
> Priority: low
> Tags: security, sync

`SyncEngine::groups_holding` (core/node/src/sync/deliver.rs) is "groups whose closure holds `t`". Since subgroups sit in their parent's closure, a group often encloses an actor it cannot read. spec/permissions.md §3 asks for the labels the removed party could read and §2 for the labels holding the holder; neither needs an encloser that reads nothing of the holder.

Likely fix: one rule for every delivery, labels that carry `t`'s bodies (`g == t` or `Engine::reads_in(g, t)`), moved into `groups_holding`, with a test like `labeling::a_removal_from_an_unread_closure_thing_stays_off_its_group_spec_permissions_3` for a removal of the listed team's own edge elsewhere. Check `tied` untie's `passed_since` use of it.
