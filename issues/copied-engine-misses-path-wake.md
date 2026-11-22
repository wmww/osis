# A copied engine misses a waiting split path's wake
> Summary: on an engine copied by `LocalPeer::copy` (`Core::test_copy` leaves `paths_wait` unset), a split commit whose entry for one thing opens nowhere, arriving in the copy's first transaction, is never opened when that thing's roles secret comes later: the debug check `apply::paths::missed` fires. A fresh engine and a restarted one open it.
> Priority: normal
> Tags: engine, tests

Reproducer: `validity::a_path_waiting_opens_when_its_roles_secret_comes_spec_commits_4` on a copy of its world (`lp.copy()` before Carol ingests Bob's split commit without D's part) panics "after a transaction: a split path's wake missed"; built fresh, or with Carol restarted at the same point, it passes. Unread cause; a lead: `apply::paths::refresh` builds its wait when `paths_wait` is `None`, taking `paths_unknown.feed()` in the transaction that adds the commit, so the commit may be neither in `fresh` nor tried.

A harness gap at least (every cached world is a copy, so a copy must behave as the node it copies), possibly an engine one if any production path rebuilds `paths_wait` mid-life the same way. The test runs on an uncached world (marked Interim) until this is fixed; then it takes `two_paths_world()` like its neighbours.
