# watchdog-1113b
- The new pointer check (policy `doc_refs`) found 30 rotted pointers on main; fixing one in the root Cargo.toml comment makes this branch's gate select every crate plus unification (issues/tooling-differential-gaps.md).
- notes/time-limits.md held a second `## Investigations` heading after Hits with five hits under it: a keep-both rebase of the old layout. Reviewers append hits at the end of Hits only.
- Rebasing the time-limits digest (which truncated the file after Hits) over a review that appended a hit dropped that hit with no conflict: after rebasing a digest, diff Hits against origin/main's.
