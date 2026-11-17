# keel-custody-23225
> Summary: Mishaps met chasing a custody seed that failed only on a stale base.

- The seed (23225252944) came from a property run on a branch still based before 33c6da055 (the device-record fix): it fails 54c2fda4e..83a5c5e12 and passes on main, the same world (same rng draws, commit IDs differing from the first commit a fetched card changes). Replay a seed on main before briefing it as a main failure; a run's base is the commit its worktree had when the binary built, not origin/main at report time.
- A branch landing after a rebase onto a fix it never ran its properties with (here end-of-history checks over 33c6da055) leaves the combination unswept at size; the end check could have surfaced new custody failures.
