# home-stranded
- The issue blamed `open.rs` and the toggle; the cause was in the payload's fallback label. `start_label`'s `g` looked right until a trace printed it: a cheap trace there would have saved the guessing. Node-level `Net` tests reproduced it 100%; the threaded `sources` world only half the time (tid order), which made it look like a race.
- Review: `wait_synced` reports any Failed connection as Stranded, also one failed by `MAX_REOPENS` or with another host open, so `Unsynced` means less than its doc says; found by reading.
