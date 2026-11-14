# The store re-encrypts about 180 pages per synced write
> Summary: Counted in the node sync tests (notes/sync-test-harness.md, measured costs): one synced write makes the receiving node's store re-encrypt about 180 pages. The work per write should be proportional to the rows the write changes; find what rewrites the rest.
> Priority: normal
> Tags: store, performance

Count pages sealed per write in a debug test at n and 10n held rows. If the count grows with n, the pager is rewriting pages the write did not change (dirty tracking too coarse, or a whole index rewritten); if it is flat but large, a write touches too many tables. The new sync code (issues/sync-rewrite.md) writes through the same store, so fix it below sync.
