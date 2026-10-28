# deaths-windows (review)
- The cold build after `rm -rf target` took 402 s for `cargo test --workspace --no-run` (notes/build.md expects about 80 s + 53 s for all targets); load was moderate. Worth a look if it repeats.
- The skipped-snapshot debug check fired on any kept text (played element creations stay as anchors); no tier-1 test covered a skipped snapshot of a sequence, and the order harness's kept text never hit it in 120 seeds. A unit-level differential (crdt property) caught the crdt side faster than the harness would have.
