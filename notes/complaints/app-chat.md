# app-chat (lodestar-app-chat)
- notes/app.md's two-device recipe said `osis serve --data DIR`: no such flag any more (`-s DIR init`, then `-s DIR serve`); fixed there.
- guibox's compositor failed to start once (EGL_BAD_ALLOC, IPC socket bind); a plain retry worked.
- `pkill -f PATTERN` from a Bash call kills the calling shell too when the pattern is in its own command line (exit 144): kill by the background task instead.
- First kit test build in a fresh worktree took about 4 minutes (past the Bash timeout): start it in the background.
