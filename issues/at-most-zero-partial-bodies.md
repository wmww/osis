# Keep-at-most 0 re-saves a whole record when an edit erases part of an older commit
> Summary: Under keep-at-most 0 an ordinary commit body that an edit only partly overwrites (some of its writes still live, e.g. a deleted word from an older typing burst) is dropped at once, so its live writes need a carrier: the writer re-snapshots the whole aspect. Snapshot bodies now wait for the next compaction (spec/commits.md §5); ordinary ones do not.
> Tags: node, spec, retention

## Technical details
`retention::check_at_most` drops a body at its first death under at most 0 unless it is a compaction snapshot; node-sync's `snapshot_first` then writes a whole-state snapshot when the dropped body still has live writes (`body_live`). Register-like aspects (a body dies whole) are unaffected; texts and maps edited in many commits pay O(state) per partly erasing edit until compacted. Option: extend the snapshot rule (keep to the next compaction or first death plus `SNAPSHOT_GRACE`) to every body that still has live writes when it first dies; needs liveness judged at the kill, alike at every node.
