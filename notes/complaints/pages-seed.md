# pages-seed
- Debug builds of osis-engine print empty function names in `Backtrace` (no symbol names in frames, only `at file:line`): filter frames by path (`/crdt/src/`) to find who noted a miss.
- A passing property captures its stderr, so debug prints vanish on success: add `--nocapture` when probing a seed that may pass.
- The seq_cold reach floors (moves 20, edits 15 per seed) sat near 2σ under the mean, so seed 13 failed the floor once its steps passed; a floor must sit under what any seed reaches.
