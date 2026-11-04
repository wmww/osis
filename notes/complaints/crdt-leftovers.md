# crdt-leftovers
- The issue's rule for the removed key (move anchors to the key-erased record) reads as one line and needs a canonical placement per anchor; `Eq` on `Fragment` is the state, so the law tests refuse it fast, which is what saved time. A one-seed random order test written first would have saved two rounds of rule attempts.
- `cargo test -p osis-crdt -p crdt-model` stops at the first failing target and hides the other's result: `--no-fail-fast` when comparing.
- Review: `.worktrees` vanished mid-review and came back with other numbers (wt7 gone, its target with it; a cold rebuild). Nothing said so. A script of `cd <wt>; cargo ...` then ran in the session's cwd: `&&` after `cd`, always.
- Review: the worker's stated gap was checked by no order oracle before handover; `seq_compact` fails on it within 40 seeds.
