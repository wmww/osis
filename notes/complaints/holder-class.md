# holder-class
- `git merge --ff-only rotation-seed` failed (main had moved past the branch's base); rebased the task branch onto it instead, which rewrote two main commits on the branch (the reviewer's `git rebase main` drops them as duplicates).
- Root-causing a property seed needed hand-written dumps (boxes, makers, departures, timeline edges, demotion frontiers) in the property file each time; a reusable "explain this leak" dump in `tests_property.rs` would have saved most of the time.
