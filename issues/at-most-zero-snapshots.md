# Keep at most 0 re-snapshots per kill
> Summary: under keep-at-most-0 retention a kill of any write a compaction snapshot carries drops that snapshot at once (spec/commits.md §5: snapshot bodies follow the same rules), so a large aspect is re-snapshotted, O(state), on every edit that kills something, and its live writes have no carrier between the drop and the new snapshot.
> Tags: node, spec, retention

`retention::note_deaths` records deaths per carrier body (`carriers`: the write's own commit and every held snapshot whose frontier holds it). With at most 0 the body goes in the transaction that applies the kill; a snapshot body is one body, so its first death drops it. spec/commits.md §5 then requires the writer to snapshot again before dropping a body with live writes (and node-sync re-snapshots under the label): one whole-state snapshot per kill, against spec/requirements.md (Scale: cost per change).

Options (spec level): exempt snapshot bodies from at-most-0 immediacy (drop at the next compaction), count a snapshot's death only when every write it carries is dead, or snapshot by page so only the touched pages are re-snapshotted.
