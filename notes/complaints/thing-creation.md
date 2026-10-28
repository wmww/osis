# thing-creation
> Summary: workflow mishaps met while making thing creation linear.

- wt2's target was 10 GB at claim (stacked generations); left as is.
- A timing script running several configs through `cargo test --release` rechecks freshness per invocation: editing sources mid-run rebuilds the next config with half-done edits. Build once, copy the test binary out of `target/`, run the copy.
- `pkill -f <script path>` killed the Bash tool's own shell (its command line held the path): exit 144, the background job orphaned.
- No `perf` on the box (and `perf_event_paranoid` 2): finding the remaining hot spots meant temporary `costs::span`s around each step, one release build per round.
