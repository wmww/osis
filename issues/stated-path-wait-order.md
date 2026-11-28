# The engine places a grant write in its commit by its own thing's path alone
> Summary: spec/permissions.md §5.1 step 1 places a commit's grant writes on a grant of a path the commit states for any thing it writes after its others; the engine's path wait (`validity::write_place`) reads only the path stated for the write's own thing, so a write on a record grant down to another thing the commit writes by a non-grant part sits apart from the walk's place for it. Recommendation: place by every thing the commit writes.
> Priority: low
> Tags: engine, perm

Where it matters: two grant writes of one commit, one on a hop of the other's stated path, the first also on a record grant descending to a thing the commit writes by another aspect (`keys.0`, `secrets.0`, `sync.0`). Honest role commits change one grant (spec/commits.md §2), so only a hostile commit can reach it, and then only its own parts' waits differ.

Why not done: a held `RoleCommit` keeps its grant writes alone, not the things its other parts write; `Held` would keep the commit's written things, or the engine would read the header back, for a case no honest writer makes. held-model places by every thing written (`World::stated`).
