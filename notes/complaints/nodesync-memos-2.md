# nodesync-memos-2
> Summary: Footguns met converting node-sync's rotations and keep bounds to memos.

- A memo whose function runs `Engine::run` depended on the transaction's upkeep too (`leave_if_removed` reading the account's timeline): a grant anywhere in the component re-judged every body's bounds (`scale::a_change_costs_a_few_passes` caught it). `Engine::run` now reads its upkeep unrecorded.
- A cache written inside a memo's own computation (`ix.departures` filled on a miss) moves the stamp the memo just read: the memo is stale at once and runs twice per change. Such a cache has to be a memo itself.
- Finding which read moved a memo took a throwaway build: a backtrace per recorded read (`std::backtrace` filtered to the repo's frames) and a print of the first failing one on a miss. Worth a debug-only "why recomputed" switch in `memo.rs`.
- `Engine::probe` rolls back, and a rollback that touched an index moves every record's stamp: a debug comparison through it re-ran every memo after it. A run that writes nothing commits nothing instead.
- An old cache's clock assumption hid in a helper (`reseal_scan` -> `finalizable` reads the time): no default test failed with the time read removed from the memo; it needed a new test.
- Every-hit builds and mutant builds of osis-node `it` take 8-25 min a run at load 40-60.
