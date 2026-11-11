# rotation-seed-9141
- `rotation_holds` failure messages name the epoch but not how the peer got it: finding that it came through a holder actor's box took a probe printing the peer's `secrets.0` boxes at first hold. A "first held via" line in the panic would save that step.
- Each bisect point is a 2-4 min rebuild of osis-engine in the worktree; three points cost about 10 min.
- A 2000-seed `rotation_holds_large` run meets two families already failing on main that had no issue or known-failure line ("lacks a box", and `reseal_due` erring Permission): each looked new until replayed on main. Issues and known-failure lines added.
- Review: each planted engine bug costs an osis-engine rebuild plus a heavy-lock property run, and the lock was held by other gates for 7+ min at a time; a plant that stops convergence (Seal at the oldest keyset) makes slow no-fixpoint seeds that run 10+ min.
