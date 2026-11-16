# Strongs in kept history hold
> Summary: Tess's idea, design study first: a per-thing boolean (likely part of the history setting, `retention^.0`) making strong references in history the thing deliberately keeps hold their targets, as current values' strongs do. Only history the setting promises counts, not history kept incidentally before a snapshot. Build and merge only if it fits cleanly.
> Priority: normal
> Tags: engine, retention, data-model

- Today only current values' strongs make a target part of the closure (spec/sync-set.md §2); a strong removed from the state releases its target even if the thing keeps that version in history, so restoring an old version can name things already gone.
- Shape (Tess): a boolean, not a separate window; tied to what the history setting keeps. Flexible on counting incidental history if that is much simpler (collection is not defined to be immediate).
- Study before building: how the closure walk and the reference index see kept versions (which rows, and their end when a version leaves history); cost per kept version; interaction with purge, expiry, compaction covers and release; hostile writers (a writer of a kept-history thing pins targets for the history's length: bounded by the setting the admin chose).
