# m2-paths
- `roles-model -- 1000000 vouches-state` under plain `tools/heavy`: the search took 14 s wall, then its shrinker (one core, rewriting every candidate's honest vouches under the state rule) held the box-wide lock for 20+ min before I stopped it. A failing world's index, printed beside the shrunk trace or before shrinking, would have been enough; scanned indices with a throwaway test instead.
- README timings in wall seconds ("1,000,000 (random, 15 s)") read as a `--short` fit; the same run is about 230 CPU-s and the lane stopped it at 117. State CPU-s for lane choice.
