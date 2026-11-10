# main-seeds
- tools/heavy waits were long (25+ min twice) for a 2 s single-seed replay; a one-seed `held_set_decides_plain` replay runs on one thread and needs no lock: worth saying in notes/testing.md.
- Neither issue file named in the brief existed on main or any branch; the seeds came only from the brief.
- No engine trace for "what happened to commit X": a temporary eprintln at `drop_part_for`/`unindex_commit` with a backtrace found both mechanisms in minutes. A permanent env-gated trace of drops and forgets per commit would pay off.
- Review: the gate went red on the known direct-redeem stall (issues/flaky-single-use-direct-redeem.md, a third test); tier 1 failing stops the gate, so the branch's selected properties and sim scenarios never ran. A known flake costs the whole selection.
