# test-width
- No tool ranks default tests by instructions: tools/limits.py measures CPU-s and only flags the limit's hits. A per-test `icount` sweep (each test its own process, 16 at a time) took 8.5 min under the heavy lock; it would be worth a `tools/limits.py icount` mode with a JSON out and a before/after diff.
- A periodic pad (`"x".repeat(n)`, a repeated format) silently changes content-defined page cuts: a 24-times repeated 23-byte string gave far fewer wire pages and broke four paged tests. Pad with hex noise.
- held-model and roles-model depend on no osis crate, so they cannot use `testenv`: each reads its own `OSIS_*` range, and nothing checks those names against core/base/testenv-known.txt at run time.
- issues/tests-4x.md pattern 5's must-fail `try_until` walks (sharing.rs, 200 steps) cost little: quiet steps are cheap (200 -> 130 steps saved under 4% of the test).
- A before/after re-measure of six crates (main and branch, every default test as its own process) in one heavy hold took 5391 CPU-s, over the 5060 hold limit (1.07x at load 32): measure the two trees in two holds.
