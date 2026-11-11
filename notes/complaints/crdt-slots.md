# crdt-slots
- The incremental `Slots` join's debug check (`join_slots`, "differs from a whole pass") prints no inputs; finding which caller handed it a non-canonical `Slots` took a temporary print and a backtrace.
- `Fragment::slot(Register)` returns `SlotRef::Frag` for a plain register and `SlotRef::Reg` only inside `Slots`: a match on `SlotRef::Reg` silently misses plain registers (the bug here).
- Review: `Fragment::slot(Register)` and `chosen_slot` now give `SlotRef::Reg` for a plain register too, so that confusion is gone. The random entry-copies generator gave one leaf per record and only three kinds, so a forged bag copy of the register write (model disagreement) needed a by-hand widening to show up.
- Review gate stopped on a rotation seed that fails on main too (issue filed); sim stage then rerun by hand under tools/heavy, 25 min of it waiting for the lock.
- Re-review: at load 30 the crdt law tests' wall times swung 1.2-7 s run to run; only `/usr/bin/time` user seconds on the test binary told whether a new check cost anything.
- Re-review gate stopped after the properties stage on a rotation seed failing on main too (issues/rotation-holds-settles-blocked.md), so the sim stage was rerun by hand under tools/heavy; `tools/bin-at main --lib osis-engine` to confirm took 55 s.
