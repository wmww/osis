# dating-cost
> Summary: Workflow notes from profiling history dating in the order properties.

- `held_set_decides_plain` prints nothing a test thread prints without `--nocapture` (its seeds run on `par_map` threads): an `eprintln!` probe needs it.
- A cost spread over many ~1% walks is hard to cut by design without touching a debug check's independence: two debug-check cuts measured, then dropped for that reason.
