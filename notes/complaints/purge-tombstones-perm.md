# purge-tombstones-perm complaints
> Summary: Workflow notes from fixing the purge_tombstones Permission failure.

- The sim's failure line names the refused thing but not which scenario step wrote it; finding the failing commit took a temporary eprintln in the scenario. A trace line per `sim.commit` naming the caller's line (or the mutation's request kinds) would have answered it at once.
- Trace "node N write" lines also count a node's own background snapshot writes, which read like scenario writes and misled the first look (node 1 appeared to author messages it never wrote).
