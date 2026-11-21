# review-sync-store-2
> Summary: footguns met reviewing sync-store-2.

- A count test with a tolerance (charged within 1.25x of held) passed with a whole index row or the blob slot dropped from the charge: the 211 B gap was one deliberate row (held elsewhere, charged before written). Writing that row in the test made the per-entry check exact; mutate a term before trusting a tolerance.
- The brief listed changes (`read_memory`/`memory_since` returning `Result`, `served_busy` failing a stream) the branch does not contain: check the claims against `git diff --stat`.
