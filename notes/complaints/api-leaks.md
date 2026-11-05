# api-leaks
> Summary: footguns met while taking implementation words out of the `osis` exports.

- A private inherent method beside a same-named trait method: rustc picks the trait's when imported, and says "method is private" when it is not. Reads like a visibility bug; it is a missing `use`.
- `sed` of `ClientConfig` in the port client hit `osis_proto::ClientConfig` too: two crates' types of one name.
- `cargo check --workspace --all-targets` stops at the first failing crate without `--keep-going`, hiding most of a port's errors.
- A test holding three commits under a fixed `ManualClock` relied on the hybrid clock's logical part to order `since`/`until`: public `Time` is milliseconds, so it advances the clock now. Other tests compare via `internals::Exact`.
