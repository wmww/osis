# drop-mem-limits
- `git revert --no-commit` of the four conn-memory commits applied cleanly and was the fastest way to drop them; the kept part (reader one read at a time) and the Link destructure then needed restoring by hand, and the revert also deleted the branch's complaints file.
- notes/decode-bounds.md pointed at a Security section of issues/sync-unbuilt.md that no longer exists.
