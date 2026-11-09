# half-valid
- `wt claim half-valid` made a branch `half-valid` at main, so the brief's `git checkout -b half-valid rotation-fix` failed; `git reset --hard rotation-fix` on the claimed branch instead.
- A TLC operator recursing to a fixpoint that does not exist dies with a StackOverflowError (run.sh reports `error`), not a violation: state uniqueness as "every fixpoint equals the result" instead of computing one.
- Depth0's `Beaten` read `ReachD` of the removed party itself, empty for an actor: `NoLeakLimit` passed or failed vacuously on actor removals (fixed: `ReachP`, its devices).
- A python string replace over a span between two markers in engine/index.rs silently deleted every impl between them (the end marker was far below the intended one); the build caught it. Check the span length before replacing.
- `ActorEpochs::newest_held` means the newest *current* held epoch, not the newest held: a test asking for an old secret got `None` (use `newest_secret`).
- The rotation property's 607 failure was an oracle false positive, not the half-valid leak the issue filed it under: `record` judged "made with the peer below" after the step, after the step's removal of a holder actor the cascade's earlier rotation had boxed.
