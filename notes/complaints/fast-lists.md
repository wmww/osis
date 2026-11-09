# fast-lists
- `cargo test` of kit and app waited 9 minutes behind another build lock; `ps` showed no test binary and looked like a hang.
- A guibox started from a shell that has sourced an old session's env fails with a confusing wdotool error flood.
- `guibox start` exits 1 silently when a window takes over 20 s (a slow seed), with the session still running; a retry that reuses the store dir races it (a store came up "corrupt: root epoch"): use a new dir.
