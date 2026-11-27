# sheave-c22-derived
> Summary: a count test comparing two worlds (copies) passed or failed by other test threads' timing through `memo::Quiet`, with no way to provoke it.

- `copies::a_copied_world_goes_on_as_the_original` passed alone and failed in a full run (1 in 2), because whether a `Quiet` follower skips depends on every thread's writes. Reproducing it took a hand patch making `Quiet::holds` fail at random (then 5-9 failures in 10).
- Would have prevented it: a test-only switch that makes `Quiet::holds` (and the `Cutoff` refresh's) miss at random, run by the copies and count tests, so a fixed point that changes a world's counts or history shows at once rather than as a rare flake.
