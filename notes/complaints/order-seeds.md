# order-seeds
- Triage of a dozen alike seeds needs a per-order dump (packs, pending, suspects, facts, state after each ingest, oracle deaths). I wrote a throwaway `dbg_seed` test in order.rs each time; a kept `OSIS_ORDER_DUMP=<seed>` mode of `run` that prints the first failing order's nodes this way would save the next agent an hour.
- Shrinking a 60-step alike seed takes 5-6 min; `OSIS_ORDER_SHRINK=0` (added) skips it when the history is already known.
- `testenv` panics on an unknown `OSIS_*` variable (core/base/testenv-known.txt): good guard, but the panic message arrives only after a full build and run; the list is easy to forget.
