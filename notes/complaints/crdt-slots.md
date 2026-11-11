# crdt-slots
- The incremental `Slots` join's debug check (`join_slots`, "differs from a whole pass") prints no inputs; finding which caller handed it a non-canonical `Slots` took a temporary print and a backtrace.
- `Fragment::slot(Register)` returns `SlotRef::Frag` for a plain register and `SlotRef::Reg` only inside `Slots`: a match on `SlotRef::Reg` silently misses plain registers (the bug here).
