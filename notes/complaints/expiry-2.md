# expiry-2
- held-model's README claims 2400 seeds pass its convergence properties; at 2400 two fail on main too (issues/held-model-props-past-300.md). A claimed seed count in a README goes stale silently.
- A `&` inside a `run_in_background` command detaches the work from the task, so `claudewait` cannot see it: easy slip when chaining two runs.
- The design note said list creations carry no value; a durable list element emptied by nested removals would then vanish. Caught by reading, before code: worth a "durable reads unchanged" check on every container when a liveness rule changes.
- Review: the rebase onto main conflicted in notes/handoff.md and notes/testing.md (main's settled-check carve-out landed beside the branch's oracle edits); resolved by keeping both.
- Fix round: osis-crdt never drops a deleted creation's char itself, so the spec's "may drop" looked removable; the engine's rebuild check then failed because paged states (snapshot encoding, rule 5) drop them. Grep the engine's uses of a crdt freedom before removing it.
