# keep-two
- Load 50+ the whole task: a 300-seed alike run took 16 min, one-test rebuilds of osis-node 5-8 min each. Diagnosing by println in the engine cost a rebuild per probe; most of the wall time was builds.
- The issue's repro read 8300296 no longer failed on main (generator moved); the internal-state repro (83028) needed an engine hack (forced retention in `framing_for`) to reach. A pinned `check` with a retention override hook in the harness would make such issues replayable.
- Rebasing onto main mid-task: local `main` lagged origin by the order-narrow merge; `git fetch && git rebase origin/main` was needed (as coordination.md says).
