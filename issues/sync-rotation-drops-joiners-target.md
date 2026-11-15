# An account's rotation drops its role commits at other accounts' nodes
> Summary: when account A rotates (a node removal, or rotate_account), another account's node taking the rotation drops role commits A wrote (grants on a thing it reads, L's grant on A's link actor K), so it loses its role, the thing leaves its sync set, and nothing fetches the commits again. Masked while a redeemer followed a link forever (K's sync ID synced from the link text regardless of roles refetched them).
> Priority: critical
> Tags: engine, sync, tests

- Seen (`OSIS_SYNC_TRACE=<node>:commit`, `-commit` lines right after the rotation's `+commit`s):
  - `driver::a_sibling_rotation_proves_again_spec_sync_opens_1` (siblings fixture): after `rotate_account(a1)`, node 0 drops two commits a1 wrote on p1 / K1; then `role_on(p1)` is None, `roster(K1)` holds a1 only, K1's and p1's sync IDs leave node 0's sync set. On main the same two commits drop and come back a few deliveries later under K1's sync ID, which the followed link kept.
  - `flows::writers_of_two_accounts_keep_each_others_certificates_spec_sync_judgement_2`: at "account 0 rotated" node 1 drops a0's grant on t (plus two commits it drops on main too, never refetched there either): `role_on(t)` None, S leaves its sync set, its store holds no copies under S.
  - `sync::an_outsider_reads_the_accounts_writes_across_a_node_removal_spec_permissions_3` (osis): after `remove_node`, the outsider no longer reads the group's write from before the removal.
- Each is `#[ignore]`d naming this issue. They pass with the redeemer's link never forgotten, and fail with the Proved rotations off too: the trigger is taking A's rotation at all, not the Proved path.
- Likely the history-less re-placing of an actor's role commits by a rotation (issues/history-less-grant.md, Fathom's lane): the originals drop and their stand-in copies travel only under sync IDs the node stops syncing because the drop removed its role.
- Fix and test: a holder keeps its role on a thing across the granter's account rotation, whatever link it follows; a minimal hand-written reproducer (two accounts, a grant, one rotation), then un-ignore the three.
