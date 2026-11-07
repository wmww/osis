# Killing a keep-at-most-0 body wholesale is quadratic in its parts
> Summary: a commit that replaces every part of an n-part body under keep at most 0 after replaced judges that body once per killed part (`check_at_most` from `note_deaths`, per aspect joined), and each judgment asks whether the body still holds a live write (`retention::bounds::live`, uncached, a state read per part of the class until one is live): about n²/2 state reads in that one apply, at every node. 120 parts: 6.2 s in a dev tier-1 run, 5.4 s of it in `live`; the same body kept at least instead: 0.3 s. Absorbed by issues/retention-modes.md (keep at most and `judge_at_most` go).
> Priority: normal
> Tags: engine, performance

Death reads are linear here (`at_most_bound` reads the class's deaths, but `pass_marks::body_judged_once_per_body_spec_requirements_scale` with a keep-at-most-0 retention counts 2-4 reads per part). The cost is `judge_at_most`'s `live(tx, c, ai)`: while later parts' aspects are not joined yet, the scan finds a live part early; as more die it scans further.

Cures to weigh: judge each killed body once per transaction, after the joins (collect the bodies in `note_deaths`' callers); or cache `live` per body within the transaction (`Core::live_bodies` caches `Engine::body_live`, forgotten per aspect on change, so it would be forgotten at every join here). Test: that pass_marks test under `History::PurgeOnReplace` and a wall-free count of state reads.
