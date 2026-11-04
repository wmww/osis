# crdt-leftovers
- The issue's rule for the removed key (move anchors to the key-erased record) reads as one line and needs a canonical placement per anchor; `Eq` on `Fragment` is the state, so the law tests refuse it fast, which is what saved time. A one-seed random order test written first would have saved two rounds of rule attempts.
- `cargo test -p osis-crdt -p crdt-model` stops at the first failing target and hides the other's result: `--no-fail-fast` when comparing.
