# Commit wakes reached by no test
> Summary: Ignoring every `Wake::Commit` in `waits::due` (core/engine/src/apply/waits.rs) fails no osis-engine `it` test, `held_set_decides` included: either another wake always covers what a held commit or a held epoch wakes, and the kind can go, or a wait on a commit or epoch has no test.
> Priority: low
> Tags: tests, engine

Find which pending reasons `Wake::Commit` is the only wake for (`Reason::Epoch`: a rotation held before its chain, a merge's tips and certificate), write the minimal reproducer that needs it (checked to fail with the wakes ignored), or drop the kind if none exists. Run the engine lib tests with the plant too.
