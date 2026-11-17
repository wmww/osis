# keel-why-kept
> Summary: Mishaps met adding `Engine::why_kept` and row dumps.

- `tools/mutate.py` prints only the failing test names, never their output: to see a failure message under a plant, run the test binary it just built (newest `target/debug/deps/it-*`) by hand before the next build replaces it.
- Several mutations in one `mutate.py` call wrap each OLD as an expression: a `.filter(...)` method-chain fragment does not build; such plants go one per call.
- A plant inside a `rooted` branch is reported under that branch's reason (`why_kept` reads the rule): plant a leak as its own clause, or outside `needed.rs`, to see a truthful explanation.
