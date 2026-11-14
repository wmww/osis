# Own commits of a read sync ID are never held elsewhere
> Summary: status's product ground answers `NotBuilt` for the store's own entries of a commit (`status/live.rs` `own_entries`), so no own commit that a read S must hold is ever judged held elsewhere: `wait_synced` on a thing this node wrote under a read sync ID never resolves, and a self-removal's dropped secrets are never released.
> Priority: normal
> Tags: sync

spec/sync-status.md §2 (held elsewhere) and §3 (a wait is synced once heard out and every own commit under S is held elsewhere). `status::held_at` first asks read's verdict; for `Verdict::Must` it reads `Ground::own_entries(s, c)`, which the product's `Live` answers `Err(NotBuilt("store: own entries by commit"))`; `skip_unbuilt` then leaves the commit unheld. `SyncStatus::synced()` needs `unheld == Some(0)`, so `Node::wait` stays `Pending` for every S where this node wrote a body S must hold, and `Engine::held_elsewhere` is never called for a self-removal (spec/permissions.md §3: its secrets drop once held elsewhere).

Build: the own entries of `c` under S as the store's own entries whose blob `Engine::commit_blobs(c)` names (both stamped, so the key stays an `Effects` key). Test: a write under a read S, a reader source pulls it, `wait(Thing)` resolves (through the osis API too: core/osis/tests/it/sync.rs has no passing wait after a write); a self-removal held at a peer releases its secrets.
