# floor-and-admin-keys
- The requirements floor test takes about 8 s at load 20, over the few-seconds budget: a commit's write and apply cost grows with the square of its things (issues/commit-cost-quadratic-in-things.md). Kept at the floor's real size rather than shrunk.
- `tools/policy.py` flags a `pub` engine method left used only by tests after a refactor; clippy then flags it dead once made `pub(crate)`: two rounds for one fix.
