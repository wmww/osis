# dating-cost
> Summary: Workflow notes from profiling history dating in the order properties.

- `held_set_decides_plain` prints nothing a test thread prints without `--nocapture` (its seeds run on `par_map` threads): an `eprintln!` probe needs it.
- One plain seed with a probe that prints per index derivation runs past `tools/heavy --short`'s 115 CPU-s lane and is refused after the fact; run probes in a hold.
- The cpuprof report on main has no TRUNCATED line yet: check `samples of` against 120,000 by hand.
- A cost spread over many ~1% walks is hard to cut by design without touching a debug check's independence: two debug-check cuts measured, then dropped for that reason.
