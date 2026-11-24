# prop-cost
- A probe's `eprintln!` in a passing property shows nothing without `--nocapture`: one 15-minute lock wait lost to a probe run that printed nothing (the Footguns line is there; easy to forget on a copied-binary run).
- cpuprof's sample totals times `CPUPROF_INSTR` give a property's instructions directly: no separate icount run is needed for old-vs-new totals, and the pickled stacks (symbolized once) answer every later "who calls X" question in seconds.
- The brief named "notes/time-limits.md, Trend", which does not exist; the per-property gate costs were recovered from reviewers' gate logs in the scratchpad (`gate: cost NAME`).
