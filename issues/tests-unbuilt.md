# Test strategy items not built
> Summary: Testing still missing: a simulator run of 10^4 seeds per scenario (needs a quiet machine) and GUI smoke tests.
> Tags: tests, sim

Repro: not built, no failing test. What is built is in notes/testing.md.

- **Sweep**: "every headline scenario green over 10^4 seeds" was never run; the largest runs are in notes/testing.md (Simulator; latest: 458-459 seeds of each of 42 scenarios green, and 4181 seeds in production round 1). A full run needs a quiet 16-core box for about 6 h (`sim-sweep --seeds 10000`, no budget or a large one); nightly runs `--seeds 10000 --budget-secs 6000`, far fewer seeds per scenario.
- **GUI**: no GUI apps yet, so no gui-testing smoke tests.
