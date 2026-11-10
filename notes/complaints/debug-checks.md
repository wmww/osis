# debug-checks
- The heavy lock was the slow part: about 2 h of 4 waiting on other agents' gates and reviewer sets for seven measurement runs. A whole-binary icount run per variant (node + osis, ~6 min each) is what made it slow; a runtime switch in a throwaway probe (one build, many runs) saved builds, not lock time.
- `#![forbid(unsafe_code)]` workspace-wide rules out an in-process perf counter for a probe; `/proc/thread-self/schedstat` gives thread CPU ns safely, good enough for shares.
- A probe logging to one file from a test binary whose tests spawn child processes of itself interleaves lines: parse defensively.
- Review: each whole-binary icount waited 15-25 min for the heavy lock behind other gates; four runs (node and osis, before and after) took over an hour of waiting for about 20 min of measuring.
