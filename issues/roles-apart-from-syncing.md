# A role through holders, with only the target synced: untested
> Summary: Tess: "a role counts wherever its grants are held; syncing is a separate choice". Built (notes/holder-access-study.md, The direction): a node syncing C holds for keys the holders C's grants name, found from C up. The multi-hop case has no test.
> Priority: normal
> Tags: sync, engine, tests

Wanted, a sync test: A, B, C independent; Bob write on A, A admin of B, B admin of C; Bob's node holds a strong to C alone. B and A are held for keys, Bob's node holds C's secrets and his write on C applies; with the strong to C gone, A and B are held for nothing. osis-sync `holding::a_holder_dropped_on_a_chain_is_held_for_keys_and_its_target_stays_spec_sync_set_2` covers one hop.

Related: own boxes only (a node holding for keys fetches every `secrets.0` page a role entry links: issues/holder-key-churn.md). spec/requirements.md stays as is ("the grantee's node syncs it once a strong reference it holds reaches it") until own boxes show the direction practical at large rosters.
