# group-index-mem
- `git checkout <file>` to drop a temporary debug print also dropped the uncommitted test edit in the same file; keep throwaway prints in a separate wip commit or a scratch copy.
- The index check compares each index's `Debug` text, so a cache inside an index (kept closures) must be left out of its `Debug`, not only out of `PartialEq`; the first sign was an unrelated-looking `inbox_retry` reopen failure.
- The old scale test's "pages loaded" for a group change read low: the open read every group state whole and left it cached, so the first change found its pages loaded.
