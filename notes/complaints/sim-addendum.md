# sim-addendum
- `tools/bin-at` for two revisions of sim-sweep took ~5 min (two full rebuilds and back); the first replay build on a warm worktree was ~2 min.
- The engine's walk takes a plain content commit only at its next update (`Held::touch_commit`, no `update_timelines` until something else moves), so any `&Core` reader of per-delta walk facts (`Paths::through`/`rests`/`resting`) mid-transaction can miss freshly applied commits; nothing checks it. `receipt::scope_of` reads `resting` the same way (its upstream-signers pass covers the gap today).
- An addendum test's two deliveries at one simulated millisecond put both in one receipt instant; the window's strict "before R" excluded the edit. Advance the receiver's clock between deliveries.
