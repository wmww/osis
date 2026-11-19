# m1-mono
- `tools/heavy --short target/debug/roles-model 20000 paths | grep ...` printed nothing: the run passed the short lane's cap and was stopped (exit 137), and the grep hid the stop line. Grep for `heavy` too, or check the exit.
- A `tools/heavy sh -c '...; target/debug/roles-model ...'` hold runs each binary from disk when it starts, so no rebuild of that crate may happen until the hold ends (build.md says so; easy to forget mid-hold while editing tests).
