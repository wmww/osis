# evil-host-quiet
- The sim trace shows node-to-host Streams as `link N -> Hub(..): Stream` (the recipient), which reads like a host push; took a while to see hosts pull nodes' logs.
- No trace of a node's judgments (why it placed or deleted an entry): finding the cause meant temporary eprintlns in `compactions`, `body_sends` and `deletions`. A per-node judgment trace keyed by commit would have saved most of the time.
- `cargo test -p osis --test it`: `runtime::a_paired_peer_serves_what_it_reads_in_process` failed once (KNOWN flake), passed alone.
