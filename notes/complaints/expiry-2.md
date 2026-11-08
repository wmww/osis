# expiry-2
- held-model's README claims 2400 seeds pass its convergence properties; at 2400 two fail on main too (issues/held-model-props-past-300.md). A claimed seed count in a README goes stale silently.
- A `&` inside a `run_in_background` command detaches the work from the task, so `claudewait` cannot see it: easy slip when chaining two runs.
- The design note said list creations carry no value; a durable list element emptied by nested removals would then vanish. Caught by reading, before code: worth a "durable reads unchanged" check on every container when a liveness rule changes.
