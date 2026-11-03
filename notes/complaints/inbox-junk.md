# inbox-junk complaints
- `Net` auto-accepts requests by default (`nodes[b].accepts`), and a test's "connected" sender is often a stranger: my burst test read as losing grants until I noticed the harness accepted them. A note at `two_persons` would have saved a probe.
- `store.put` in a test notifies no subscriber: the node must be offline and reconnect to see it, or the test passes for nothing.
- A test blob planted with `store.put` skips the host's prefix check: `vec![i; size]` parsed as an expired prefix and the node silently forgot the entry while the host held it.
