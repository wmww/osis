# seq-gaps
- A crdt edit costs a 1.5-5 min osis-engine lib rebuild before a 2 s property replay; most of the task was waiting on probe builds.
- A placement held in part reports misses and bail-outs as bare bools: finding the walk that noted every block took an env-gated backtrace in `Partial::block`, and the follow's give-up site a script rewriting every `return false` into a probe. A probe naming the miss or bail site would have saved several builds.
- The issue's guesses (rows joining several records; a walk in `seq::Layered`) were both wrong: the walks were `iter_from(..).take(n)` over stubs and `range_of`'s `unwrap_or(0)`. A probe build is cheaper than trusting a suspect.
- A passing test's stderr is captured: a probe on a passing replay needs `--nocapture` (cost one rebuild-free rerun, but a confusing empty grep first).
