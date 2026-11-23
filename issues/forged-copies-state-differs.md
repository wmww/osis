# A forged-copies seed leaves one node's aspect state apart
> Summary: osis-engine lib `retention::tests_forged::forged_copies_fail_no_node_large` fails on main at `OSIS_FORGED_START=814836346267 OSIS_FORGED_SEEDS=1`: "state of Tid(..) Ak("x:f.0") di[ffers]", with a panic first in `apply/atomic.rs`. Cause not read.
> Priority: normal
> Tags: engine, security, tests

Replay: `OSIS_FORGED_START=814836346267 OSIS_FORGED_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact retention::tests_forged::forged_copies_fail_no_node_large` (0.4 s). Seen at the seq-runs gate; fails the same on main's binary.
