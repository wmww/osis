# a1-header-2
- Comparing a scale number with main means switching the worktree to main and back: each switch rebuilds osis-engine's test binary (about 4 min), so three probes cost a quarter hour. A main-built `it` binary kept by `wt` per base commit would make "what does main print" a lookup.
- `scale::expiry_is_flat` and `scale::purge_on_replace_pays_its_state` flip on any change of commit IDs: their store bytes at n move by one encrypted B-tree unit (4-8 KB) as keys land in other pages (expiry 0 at n: 5 `u` rows on the branch, 6 on main, 10n alike). Any header byte change trips them.
- The previous worker's list of failing tests left out `resnapshot::owed_resnapshot_waits_for_delete_keys` (an order-dependence bug commit IDs exposed): run the whole crate suite before reporting.
