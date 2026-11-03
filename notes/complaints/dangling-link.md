# dangling-link
- Diagnostics dedup on (kind, commit, tids), not detail: two reports for one thing in one read collapse to the first. A test expecting one diagnostic per bad link timed out (20 s) instead of failing fast; report one per read.
- port/codec.rs `KINDS` had silently missed `OwnWriteInvalid` (`unwrap_or(0)` sent it to remote clients as `BadInput`); a new `DiagnosticKind` variant compiles without touching it. Added both; an exhaustive match there would catch the next one.
- Box at load ~70: a `cargo build -p osis` took 5 min.
- Review: `events.queue` outside an `Engine::run` closure is never flushed until some later transaction (a watch test timed out); queue from `tx.core.events` inside the run.
