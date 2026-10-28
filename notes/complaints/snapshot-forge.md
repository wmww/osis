# snapshot-forge
- `walks::reached` counts dropped parts by matching `" {} "` in `index_digest` commit lines: adding a field to that line (an empty set) silently zeroed the count and failed the reach assertion far from the cause. Fields go after the view (`missing {..}` last).
- The debug in-place-vs-`rebuilt` assertion in `unmerge_fell` runs a whole rebuild per un-merge: a debug `eprintln` per write inside `rebuilt` turned a 6 s test into 4 min. Print only the aspect/records of interest.
- `rebuilt` runs inside `apply_verified` before the commit's record is stored (an invalid delta arriving): `held_parts` of that commit is empty there though its meta says held. Anything keyed on "held per meta" in a rebuild must use what the rebuild actually loaded.
- Foreground test commands that compile past 180 s get moved to the background mid-pipe; a `| head` on such a command then reports the pipe, not the test. Write to a log and grep it.
