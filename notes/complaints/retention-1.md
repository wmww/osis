# retention-1
- `fill::no_pass_before_order_0_spec_sync_6` counted every blob fetched at one host, so it passed only while the held rotation's blob ID fell in the first order-0 batch; any header byte change (here the retention encoding) moved it. Now counts message blobs only.
- A tier-1 run started before a burst of test edits reported failures from the stale tree; wip-commit and edit nothing while it compiles.
- `Value::uint` saturates at i64::MAX, so a `Duration::MAX` written into `required.0^` arrives as 2^63 - 1, not above it: range checks on stored durations need `>=`.
- Reviewer: `cargo test --workspace` in libs/kit took 843 s at load about 40 (a GUI rebuild after osis changed), the held-model survey 714 s wall for 522 CPU-s.
