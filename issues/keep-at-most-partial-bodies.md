# Keep-at-most re-saves a whole record when an edit erases part of an older commit
> Summary: Under a relative keep-at-most (any D, 0 included) an ordinary commit body that an edit only partly overwrites (some of its writes still live, e.g. a deleted word from an older typing burst) is dropped at its bound with live writes, so a writer first re-snapshots the whole aspect as its carrier. Compaction snapshots get `SNAPSHOT_GRACE` and go at the next compaction (spec/commits.md §5); ordinary bodies do not.
> Tags: node, spec, retention

Repro: no failing test; a text under `keep_at_most: 0s` edited in several commits, then a delete of part of an older commit's text: the next pass writes a whole-state snapshot (`sync/pass.rs` `snapshot_first`).

## Technical details
`retention::check_at_most` drops an ordinary body at first death (D = 0) or by timer at first death plus D; the timed-delete loop and the must-not-hold path in `sync/pass.rs` call `snapshot_first` when the body still has live writes (`body_live`). Register-like aspects (a body dies whole) are unaffected; texts and maps edited in many commits pay O(state) per partly erasing edit until compacted. Option: give every body that still has live writes when it first dies the snapshot rule (bound plus `SNAPSHOT_GRACE`, the next compaction drops it); needs liveness judged alike at every node.
