# test-speed-4
> Summary: Footguns met converting the custody seeds to a `_plain` and probing the sync forensic test's cost.

- `testenv::Cpu` around `World::forensic` read 0.5 CPU-s for an attack that counts 39 G: the attack's own `par_map` threads are not in it. Count attacks with `tools/icount` and a probe that skips them.
- The forensic test's two attacks are not two costs: `Failed` (thread-local) carries the first attack's tries to the second, so dropping either device saves little; measure each alone before cutting one.
- notes/test-harnesses.md says a `_plain` "reads no environment" while range `_plain`s (seq cold, custody) read `OSIS_*_START`; the brief and the note disagree on the form.
