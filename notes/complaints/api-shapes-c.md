# api-shapes-c
- A test expecting an error at a deadline, once the deadline goes, panics only when its guard runs out: found them by a script listing `Err(..)` next to each waiting call, before running anything. `common::block_on` had no bound at all; it has one now.
- A rename by two seds (`AspectKey` to `RawKey`, `ApiKey` to `AspectKey`) turned the aliased re-export into `AspectKey as RawKey`: read the re-exports after.
- `echo exit $?` at the end of a backgrounded `cargo test` makes claudewait report exit 0 over a failed run. Read the log's `test result` lines.
