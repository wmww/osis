# inbox-two
- `claudewait` is not on PATH in subagent shells; ran it from the plugin cache. One call took >110 s and was itself moved to the background.
- Box load 30-55 during the task: each one-test probe of osis-node took 2.5-5 min (relink of the `it` binary dominates), so the issue-2 probing cost about an hour.
- `OSIS_SYNC_TRACE` printed raw byte arrays for Send actions; the net harness now decodes frames both ways (send and recv), which found the Fetch loop in one run.
- The unmet-sender "cheap step" brief assumed a sender can see an acceptance; it can't (no channel), found only by probing. A quick "what does the sender observe?" check in the brief would have saved the time.
