# rotation-class
- The rotation property's failure log names steps but not what each step made or boxed: tracing a seed meant ad-hoc eprintln probes, and `check`'s `ep` closure borrows `run`, so a probe calling into an engine needs restructuring first. A `debug` dump of each actor's boxes (holder, role, epoch, keyset) on failure would have saved most of it.
- The tally line only shows with `--nocapture`; a passing run prints no seed count.
- In the engine harness every peer receives every commit (no label encryption), so a node "knows" departures from actors it cannot read; seeds can reach shapes the node cannot, and a fix judged there can break the real node (here: judging keysets by order cut a holder off where the sealer cannot follow it).
- Review: `ever[d]` holds what the departed peer's own node opened, so an oracle excusing one box must also drop the excused secret from `ever`, or the narrowed check still sees it.
