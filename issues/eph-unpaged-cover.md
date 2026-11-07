# Ephemeral size limits: residuals
> Summary: Ephemeral deltas never page (`Unpaged`), so a commit whose delta on one aspect does not fit a blob is refused whole (`Misuse`), and a memory compaction snapshot of an aspect whose state does not fit a blob cannot be built: its bodies are never covered and pile up to the caps. Pages on the memory path lift both (memory page blobs in Core; eph-unify step C moved the bodies onto the durable sync path but kept `Unpaged`).
> Priority: normal
> Tags: engine, ephemeral

- `Engine::write` maps the build error to `Misuse("an ephemeral delta does not fit a blob")` (test `ephemeral::delta_past_a_blob_refused_spec_commits_2`); an undo whose inverse does not fit fails with the build error.
- `compaction_snapshot`/`coalesce` of a state past a blob fail at the build; `memory_compactions` reports nothing and weighs the aspect again once its held cost doubles. Writes on it keep going as separate entries until the node and host caps refuse them.
