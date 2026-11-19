# g-needs-2
> Summary: Footguns met finishing the certificates rule.

- `Peer::pulled_anew` fills only at `receive`/`reexamine` (`Peer::wake`): an engine commit's pull anew (a test's own `strong`) stays in the engine's wakes, so a test clearing `pulled_anew` after a copy still sees the setup's pulls at the next receive. Call `reexamine` before clearing.
- A thing re-entering the node closure usually rejoins the sync set by its own sync ID (pulled from the start anyway), so a re-entry test passes with `refetch` broken; only a dependent thing in a unit whose sync ID never left exercises it.
- `parts.rs`'s observer (`Peer::new(FRESH)`) got none of `share_top`'s grants, so it never read a thing outside G; the grants were in `access` but dropped from `Played`.
