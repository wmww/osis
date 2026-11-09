# A certificate copy stays deferred after chat join and leave
> Summary: sim `chat_join_leave` can end with a node holding a deferred certificate copy (`copies_waiting`), the known departure's rotation never running; fails on main too. Property: a copy waiting for a rotation is placed once the rotation runs, or goes when moot.
> Priority: normal
> Tags: tests, node-sync

Found by a branch sweep at a random offset (the seed reproduces on main). Investigate why `uncovered` stays nonempty at rest.
