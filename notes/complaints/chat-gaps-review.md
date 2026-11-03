# chat-gaps (tiller-chat-gaps-review)
- `cargo test -p osis --test it a b` is a clap error (one filter before `--`); after `--` filters OR with the first, so a narrow run ran everything.
- A test helper's `w.until` panics on timeout, hiding the state a hang is in: `catch_unwind` to read the stuck node. A redeem that never ends reports nothing to its caller but the timeout.
