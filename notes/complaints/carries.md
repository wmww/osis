# carries
> Summary: Mishaps met making the engine read a snapshot's carries (mizzen-carries).

- The brief's design (the snapshot's reading lists what it carries; touch the snapshot when a carried commit arrives) is quadratic for commits arriving after their snapshot, and no counter showed it: the list had to be counted (`snapshot: carried commits`) before `scale::commits_after_their_snapshot_are_linear` could see it. The design question took longer than the build.
- `validity::split_commits_waiting_on_a_path_cost_an_unrelated_write_nothing` passed on main only because a debug build's read (`check_missed_wakes`) rolled back and ate the pending touch of the commit just ingested: a release build walked it in the next transaction. A test of cost that holds through a bug gives no warning when the bug is fixed; the brief's "must pass" read as a constraint on the fix where it was a second finding.
- A re-read commit was reported as new by the walk whatever its reading, so every touch (each `put_meta`) re-judged its commit: found only by a backtrace probe on `carried`. A count of commits given again unchanged would have shown it.
- `tools/heavy --short` stops a single-seed `held_set_decides_plain` replay at 115 CPU-s (it needs about 120) and then refuses the command for good: a seed replay needs a full hold, which queued 15 minutes behind a gate.
- Array literals evaluate every element first: `for (ch, now) in [(p.add(..), a), (p.forget(..), b)]` runs both updates before the first assert.
- The seed replays and the default run each need the engine's `it` rebuilt (2 to 4 minutes after any perm edit): five probes cost most of an hour of builds.
