# box-retake
> Summary: review mishaps on the box-retake branch.

- Planting faults by `sed` then reverting with `git checkout <dir>` also reverted the uncommitted test under review in that dir; commit (wip) before planting, and revert only the planted file.
- `granted()` syncs every peer, the observer included, so a "late" observer already held the group's creation and no pending read ever happened: the first differential passed with the bug planted. Check a fault fails before trusting a new property.
