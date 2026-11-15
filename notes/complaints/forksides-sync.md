# forksides-sync
- `World::run` panics at its quiet checks, so a probe that wants to look at state after a failing run must wrap it in `catch_unwind`; a `run_unchecked` would save a step.
- The order property's mismatch print dumps whole 96-byte signatures per row, thousands of columns wide; printing only the differing keys would read faster.
- A test that delivers commits in a chosen order at a fresh node is hard to write: what is on D pends until D's creating commit, which carries `account.0` itself, so "a removal on D before D's `account.0`" cannot be arranged by order at all.
