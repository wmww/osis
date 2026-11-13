# key-removal-final
- The seed sweep waited on the heavy lock behind another gate for a long stretch; nothing else to do in the meantime but notes.
- A failing proptest run writes `props.proptest-regressions` silently; easy to commit a pinned seed by accident (`git status` before committing).
- The property sweep (6 crdt test modules x 500 seeds under tools/heavy) ran 6.9x the heavy CPU limit: the size was my pick (about 70 CPU-s per seed at load 16-23), not a regression; 200 seeds would have told the same (only the known forged-entry-copies failure).
