# grant-reach-review4
> Summary: mishaps while re-reviewing grant-reach.
- `grep -E "test result"` on a plain `cargo test --workspace` prints a line per test binary, 14 lines for a probe that ran in one: filter `test result: [^o]` or the non-zero ones.
- `timeout 170 cargo test --workspace` on a warm tree was not enough after a change to the engine (rebuild plus tier 1): killed with nothing to show; run it in the background from the start.
- A `claudewait` on "the newest file in the tasks dir" waited on another agent's task: the dir is shared; use the id the tool returned.
