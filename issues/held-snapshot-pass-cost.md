# A held snapshot makes each write's pass work grow with the aspect's history
> Summary: With one compaction snapshot held on an aspect, every write's node-sync pass runs `covered` against it for a number of commits that grows with the aspect's held headers: `growth::own_cover_work_per_write_is_flat` (three writers replacing one register) does 130 cover joins per six writes after 12 writes and 666 after 126. On main too (one explicit `compact` after six writes gives the same numbers); the compaction trigger makes a held snapshot the normal state, so this is now on the default path.
> Priority: normal
> Tags: node, sync, scale

Found while turning durable compaction on (branch durable-compaction). The calls come from `must_hold` (pass/bodies.rs, `covered_noted` per snapshot under the label) for the commits each pass judges; "pass: bodies of a commit" grows 79 -> 230 per window. Not yet known: which change marks the old headers' commits touched on every write (they hold no body: dropped under own replaces or the snapshot). Find what puts them in the work set, keep it O(change).
