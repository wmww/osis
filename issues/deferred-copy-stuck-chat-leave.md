# A certificate copy stays deferred after chat join and leave
> Summary: sim `chat_join_leave` can end with a node holding a deferred certificate copy (`copies_waiting`), the known departure's rotation never running; fails on main too. Property: a copy waiting for a rotation is placed once the rotation runs, or goes when moot.
> Priority: normal
> Tags: tests, node-sync

Found by a branch sweep at a random offset (the seed reproduces on main). Investigate why `uncovered` stays nonempty at rest.
- Seeds: 32 fails on main at 6b1fb2989; with own replaces (zero-growth-1) seeds 1 and 32 fail. Seed 1's copy left is a role commit (`keys.0`, `secrets.0`) of another thing, deferred as `unwrapped` (no current read secret of the group, waiting for a re-seal), not as uncovered.
