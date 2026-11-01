# paged-failures
- A failure inside the engine (the un-merge debug assertion) or in `seen`'s stale-pages assert prints no step and no history; `differential` only prints the log when states differ. Each seed needed a hand-made debug patch (eprintln of every step, commit and delivery) to see what happened. A panic hook or `catch_unwind` around each step that prints `log` would save that.
- The engine's in-place un-merge debug check fired mid-stream (after one piece of an invalid delta), looking like a product bug; it was a check placed per piece, not per part.
