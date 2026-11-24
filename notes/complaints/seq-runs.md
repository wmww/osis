# seq-runs
- Finding who noted a placement miss: a temporary `Backtrace::force_capture` in `Partial::block`/`chunk`, frames filtered to `/crdt/src/`, names the call path in one run (no symbols in debug, but file:line is enough).
- Comparing real work before/after a paging change: a temporary env toggle around the new path plus an `eprintln!` of `m.work` per `absorb` gives paired totals from one build; drop both before committing.
