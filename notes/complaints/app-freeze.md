# app-freeze
- The first kit/app test build in a fresh worktree took about 20 minutes at load 27-30.
- cpuprof's report symbolizes against the binary on disk: rebuilding before reading the report gives garbage frames; copy the binary or report first.
- In a guibox session, sourcing a previous session's `env` before `guibox start` makes the new compositor fail to start ("log: No such file").
