# stripped-cover
- A `cargo test` started in the background before the source edits finished compiled a mix; the first "fails before the fix" run proved nothing and had to be redone with the fix switched off. Edit first, then start the build.
- 300 plain seeds plus 80 exhaustive under `tools/heavy` is about 35 min of lock (one 554 s lock wait); both overrun the `heavy` limit by size alone.
- Review: the first gate died in its policy stage in 25 s: main carried known_failures lines for two issues already deleted (fixed on main by capped-refresh meanwhile; my copy of the fix dropped out in the rebase).
