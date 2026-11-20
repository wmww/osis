# vouch-thing-review
> Summary: Mishaps met reviewing the per-thing vouch rule.

- `cargo test ... -- --ignored paths:: _large` ORs the filters and ran every crate's `_large` property past the short lane's cap; name the tests with `--exact` (the worker hit the same).
- The engine harness's `vouch` helper commits through the writer rules, so a hostile voucher (no role in its own reading) needs the vouch inlined with `skip_writer_rules` and `unchecked`.
