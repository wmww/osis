# A role through holders, with only the target synced: untested
> Summary: Tess: "a role counts wherever its grants are held; syncing is a separate choice". A unit carrying C carries the stubs of (spec/sync-set.md §2 Stubs) the holders on its chains to C. The multi-hop case has no test.
> Priority: normal
> Tags: sync, engine, tests

Wanted, a chain-stub test (R4): A, B, C independent; Bob write on A, A admin of B, B admin of C; Bob's node holds a strong to C alone. B's and A's stubs are carried, Bob's node holds C's secrets and his write on C applies; with the strong to C gone, the stubs go.

Related: own boxes only (a stub holder fetches every `secrets.0` page a role entry links: issues/holder-key-churn.md). spec/requirements.md stays as is ("the grantee's node syncs it once a strong reference it holds reaches it") until own boxes show the direction practical at large rosters.
