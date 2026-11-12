# move-wakeup
- The flaky wait reproduced only with many copies on few cores (16 copies of the test binary under `taskset -c 0-1`: about 1 in 130 runs); 72 isolated runs never showed it. A stress script like that is the quickest first step for a gate-only flake.
- Tracing node-sync needs an env-gated `eprintln!` in the engine (the driver thread's output is not captured by libtest, so it lands in the run's log interleaved): cheap, but every probe costs a 1-2 min osis rebuild.
- Review: the gate waited 39 min for the heavy lock before its 11 min run.
