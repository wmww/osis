# first-admin-a
- The model branch cherry-picked with conflicts in Depth0.tla/MC/README/run.sh and every cfg (a constant added on both sides): each side's new cfgs lacked the other's constants; TLC only reports that per instance.
- `git checkout <file>` to drop debug lines also dropped an uncommitted real change in the same file (flows/mod.rs). Commit before every debug probe, not only before fix-disabled runs.
- A put then remove of one map key in one batch nets to nothing in the CRDT (no tombstone): a removal of an edge with no entry needs its tombstone minted directly.
- Tier 1 under load 20+ took 11 min; the sim cost test needed main's binary (`tools/bin-at`, 5 min each) to see the baseline.
- Review: the order harness's `run` changes `Cfg` (`sync: true`) before `check`, so a shrunk `h` replayed with `check(seed, &h, LARGE)` passes; replay with `Cfg { sync: true, ..LARGE }`. The printed replay line shows the pre-`run` Cfg.
- Review: `tools/bin-at origin/main` with `--take` for a main comparison took 10 min at load 35 (full engine+node rebuild, then the branch rebuild after).
