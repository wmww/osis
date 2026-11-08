# chat-one-aspect
- A release bench after any engine edit rebuilds osis-node's `it` binary (6.5 min at load 25); a bench running from `cargo test --release` also rebuilds silently when a source changed meanwhile. Copy the release binary to the scratch dir and run it directly for long benches.
