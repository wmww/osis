# churn-944
- The churn harness's failure dump names the missing commit but not its history; finding where it went took a throwaway per-step trace (entry kind, engine meta, tombstones, forgotten headers for one commit) plus a backtrace on `take_meta`. A test-only "why is commit X gone here" dump (last drop/forget with cause) would have made it one run.
- The earlier issue text pointed at tombstones; the cause was in the engine (a forget), invisible from node-sync's dump.
- 500-seed property waited on the heavy lock behind another agent's run.
