# held-adapter
- Order-harness shrinks run for minutes per failing seed with no output; use `OSIS_ORDER_SHRINK=0` for triage, and `--nocapture` to see `eprintln!` from seed threads (captured otherwise, even with the run's own `visible` lines showing).
- Engine mutants that change a check's helper (`purge::names`) also change the per-node checks, so a mutant for a new oracle must sit below both (`holds_right` did).
- Review: `Engine::body_not_dropped` is false for leftovers too (`Meta::body_gone`); the adapter read every leftover as dropped, which looked like an open spec question (AMBIGUITIES 24). Read an accessor's definition before trusting its name.
