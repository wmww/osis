# floor-and-admin-keys
- The requirements floor test takes about 8 s at load 20, over the few-seconds budget (issues/commit-cost-quadratic-in-things.md): at the floor's size it is an ignored `_large` test the gate's properties stage runs; the default test runs the shape at 300 things.
- Review: `perf record --call-graph dwarf` gives one-frame stacks on this box, so no callers for a profile.
- `tools/policy.py` flags a `pub` engine method left used only by tests after a refactor; clippy then flags it dead once made `pub(crate)`: two rounds for one fix.
