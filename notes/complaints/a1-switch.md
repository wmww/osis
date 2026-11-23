# a1-switch
> Summary: Mishaps met switching the engine to osis-perm's `paths` walk.

- The reading list (spec/permissions.md alone is 110 KB, perm-paths 56 KB) plus the engine's seam (`held.rs`, `validity.rs`) is most of a session before a line is written; the brief's "delete, then make it compile" hides that rustc reports only unresolved imports until every one is fixed, so the engine's real error count is unknown for a long while.
- `Paths` took records at construction only and numbered parts by position, both of which the engine cannot give (records arrive, a commit's edge ops resolve late): the walk needed `sync`, `add_record` and `PartKind::None` before any wiring.
- A wide `rg` over the engine for a common word (`certificates`, `walks`) prints hundreds of long lines: search the one file, or `-c` first.
- The engine reached the old walk through a few seams (`Timelines::get`, `On`, `validity::Judge`, `timelines_changed`); keeping `RoleCommit` and (commit, op) IDs in the query layer made most of the 250 call sites compile unchanged. The brief's per-file list overstated the churn and understated the model questions (snapshot carries, the epoch rule's addenda, sides defaults).
- `tools/bin-at REV OUT --patch` made the scale test's count on main a five-minute question (two builds); guessing at it from the branch cost most of a session's budget for that test before.
- The gate-size engine properties (`--ignored evidence:: order:: role_paths::`) were first run in the sixth session, after everything default was green: the held-model differential should run as soon as the engine's tests build.
- The brief's replay line (`OSIS_ORDER_SEED=0 OSIS_ORDER_LEN=60`) runs one seed: the property's verdict needs the run with no seed set, which is what the gate does.
- roles-model `paths` judged content at write only and exposed no request's right: "held-model reads roles-model's judgment" needed three small additions there (`needs`, `vouchable`, `judge_rights`) before any held-model line; the sizing had counted it as a builder alone.
- `claudewait` takes the task ID the tool prints (`bcxi8xyzm`), not a `bash_N` name.
- Deleting roles-model's pre-path models (`joint`, `edges`, `trust`, `addenda`, `content`, `forget`) was a code change of minutes and a citation sweep of a dozen notes and issues: their result sections (notes/addenda.md Addenda model, notes/disputes.md Model results, issues/zero-growth.md) now report a model that is in git history only, and still owe the notes rewrite.
