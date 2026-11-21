# story-cost
> Summary: Footguns met cutting roles-model's story-search cost.

- `tools/cpuprof_report.py` symbolizes with `--no-inlines`, so `walk`, `answers` and closures fold into their callers and a hot leaf shows only as its caller's self time. An inline-aware pass (`llvm-symbolizer --inlines`, counting each sample's innermost roles-model source line) found the real sites (`record_hops` per pass, the evidence closure's rebuilt sets).
- Wall and CPU-s A/B runs on the shared box drift 20% between back-to-back runs; `tools/icount` on a 300-world driver run gave stable counts.
- `tools/heavy --no-fail-fast cargo test ...` is taken as heavy's own argument and runs nothing useful: the flag goes after `cargo test`.
