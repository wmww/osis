# Deep member chains cost quadratic memory in the departure walk
> Summary: `rotation::collect` keeps each departure's whole `via` chain, so a chain of L actors with secrets of their own holds O(L^2) actor IDs per walk and a cascade (`ensure_rotated`, one walk per actor) takes O(L^3) time; the old 8-actor cap bounded this. Fine at realistic depths, a cost lever for an admin who builds a very deep chain below a shared group.
> Tags: engine, permissions

Every consumer reads only `via[0]`, `via[1]`, `via.last()` and the first actor's verdicts (the class key), plus `covers`, which walks the whole chain (now a loop, so no stack limit). A shared-suffix representation (a departure = first actor + the index of its inner departure in that actor's found set) would make a walk linear in the found classes. Also, a cascade recomputes `departures` for each actor after every rotation (each rotation clears the cache): reusing the inner actors' found sets across one cascade would cut it further.
