# addenda-memo
> Summary: Workflow snags met while making the addenda decide an `Effects` value.

- A foreground `cargo test --no-run` on osis-engine at load ~35 took 2.5-6 min wall: start every engine build in the background from the first one, not only long runs.
- `tools/logrun ... ; rg ...` in one call: when the call moves to the background, the `rg` runs on the half-written log and the call's output shows the wrong exit; keep the read in its own call.
