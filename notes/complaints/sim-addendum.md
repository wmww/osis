# sim-addendum
- `tools/bin-at` for two revisions of sim-sweep took ~5 min (two full rebuilds and back); the first replay build on a warm worktree was ~2 min.
- An addendum test's two deliveries at one simulated millisecond put both in one receipt instant; the window's strict "before R" excluded the edit. Advance the receiver's clock between deliveries.
