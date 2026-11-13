# capped-eph complaints
> Summary: Workflow notes from fixing the full peer that kept ephemeral entries no node held.

- `lane_dump` (the random-window failure dump) shows an entry with no body as `0 B` but not why: whether it is forgotten, as what, and what carries it. A temporary line printing `Memory::forgotten` (why, `carriers_of_forgotten`) found the cause at once; the dump could carry it.
- Two `net.hosts[s].hub.store()` calls in one statement (e.g. both inside one `eprintln!`) deadlock silently: the first guard lives to the statement's end. The test sat at 0 CPU for 9 minutes under libtest's "running for over 60 seconds" with no backtrace (the seed runner's hang detection covers only seed runs).
