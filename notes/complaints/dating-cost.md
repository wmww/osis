# dating-cost
> Summary: Workflow notes from profiling history dating: the order properties, the held-writes test cost.

- `held_set_decides_plain` prints nothing a test thread prints without `--nocapture` (its seeds run on `par_map` threads): an `eprintln!` probe needs it.
- A cost spread over many ~1% walks is hard to cut by design without touching a debug check's independence: two debug-check cuts measured, then dropped for that reason.
- `tools/heavy` waits behind a gate's hold (12 minutes once): queue the main-side and branch-side whole-binary counts in one hold each, never one per binary.
- Per-module counts of the engine lib (`icount BIN -q MODULE::`, every module in parallel) show where a binary grew in one hold of about a minute; the rotation module was most of it.
- A wrapper Rows counting the store reads (row_pages tests' `Counted`) is the cheap way to pin "reads no stored page", where a cost counter would need the engine.
