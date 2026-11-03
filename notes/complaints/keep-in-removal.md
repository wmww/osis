# keep-in-removal
> Summary: Mishaps on the keep-in-removal branch.

- `Engine::now_ts` reads the wall clock with counter 0, behind the HLC under a fixed test clock: a "now" key ordered before settings just written. `hlc.peek()` is what the next commit gets.
- `cargo test --workspace` stops at the first failing package; `--no-fail-fast` shows them all.
- `arrival_order_alike_large` at `OSIS_ORDER_SEED=106342` (`OSIS_ORDER_LEN=60`) fails on main too, the same way: a body dropped in one order, missing in another, after a flip. Unrelated to this branch; noted here until someone looks.
