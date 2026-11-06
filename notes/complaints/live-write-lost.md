# live-write-lost
> Summary: shrinking a settled order history is hopeless; the held-model adapter hides purge-vs-drop order; bin-at with taken test files is the way to pin.

- `OSIS_ORDER_SHRINK=1` on a settled history (60 steps plus about 700 settle steps, a check of 1-25 s per dropped step) printed nothing in two hours; killed. A targeted pin (one delivery of the failing order plus the oracle, 3 s) replaced it.
- `tools/bin-at main OUT --take core/node/tests/it/order.rs --take core/node/tests/it/held.rs` builds main with the branch's tests in about 90 s: the quickest way to see whether a pin bites. A hand-built shape passed on main twice (the creation copy vouched, the expiry stripped instead of dropping) before the seed's own order was pinned.
- `./target/debug/deps/it-*[0-9a-f]` also matches `it-<hash>.d`: name the binary exactly.
- Review: an engine-only rebuild of the node test binary took 10 min at load 25 (two other agents' builds); three such builds (branch, bin-at main, probe) were most of the review's wall.
