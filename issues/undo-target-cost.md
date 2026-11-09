# undo_target costs O(aspect history) per render
> Summary: `undo_target` runs the undo's own writes, and `kept_before` reads, decodes and joins every kept earlier part of the target's aspects. The about chip calls it on every page refresh. Slow on long-edited fields; a per-generation cache cannot help.
> Priority: normal
> Tags: engine, kit, osis

- Release, MemStore, one kept-history text field, per call of the probe: 25 commits 3 ms, 100 commits 11 ms, 400 commits 220 ms right after a commit to that field; 1 ms, 3 ms, 14 ms after a commit elsewhere. The target search itself is under 1 ms at 400.
- The cost right after a commit grows faster than the history.
- A cache keyed on `generation` misses in both cases: any commit steps it. A key must be the target and what its aspects hold.
- Likely fixes: find what is cold after a commit to the field (not yet traced); stop `kept_before` at the newest kept whole reset; let the check answer `Superseded` without the full pre-state.
