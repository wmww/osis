# "Keep nothing old" retention re-saves a whole record on every erasing edit
> Summary: For a record set to keep nothing old (keep-at-most 0, the privacy setting that erases overwritten data at once), every edit that overwrites or deletes something forces the writer to re-save the whole record as a new snapshot (slow for big records) and leaves a short window with no server copy of the live data. The spec text causes it; three ways out are listed, all small spec choices.
> Tags: node, spec, retention

## The decision (user terms)
- **Keep the rule** (current): correct, private at once, but a big record under this setting costs a full re-save per erasing edit.
- **Drop the old snapshot at the next compaction instead of at once**: cheap edits; the erased data lingers inside the old snapshot until the next compaction (bounded by the compaction interval), so "at once" becomes "soon".
- **Count a snapshot dead only when everything it carries is dead**: cheap edits; erased data lingers in the snapshot until the whole snapshot is replaced.
- **Snapshot by page**: at-once privacy and cheap edits, at the cost of a more complex snapshot format.
Recommended: drop at the next compaction (the privacy promise of keep-at-most 0 already allows the delay servers need to act).

## Technical details

`retention::note_deaths` records deaths per carrier body (`carriers`: the write's own commit and every held snapshot whose frontier holds it). With at most 0 the body goes in the transaction that applies the kill; a snapshot body is one body, so its first death drops it. spec/commits.md §5 then requires the writer to snapshot again before dropping a body with live writes (and node-sync re-snapshots under the label): one whole-state snapshot per kill, against spec/requirements.md (Scale: cost per change).

Options (spec level): exempt snapshot bodies from at-most-0 immediacy (drop at the next compaction), count a snapshot's death only when every write it carries is dead, or snapshot by page so only the touched pages are re-snapshotted.
