# port-codec
- osis has `[lib] test = false`, so a `pub(crate)` codec cannot get unit tests; the round-trip tests reach it through `internals::Port` and `internals::port_commit_address` (`commits::Address` is crate-private).
- `Value::uint` saturates at `i64::MAX`, so an out-of-range `Ts` (n >= 2^63) cannot be written as a test literal; use a wrong-typed value to test refusal.
- The old label streaming test (`scale::large_value_work_is_linear`, `multi_gb_value_streams`) checked `ValueWriter`/`StringReader`, which no app path used: the API reads through `ValueStream` and writes whole (`set_stream`). A green memory check on a side path gave false assurance.
