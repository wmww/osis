# incremental (test-design step 6)
- `pkill -f <pattern>` matched the agent's own bash command line (the pattern was in it) and killed the shell mid-edit; use `ps ... | awk` on the binary path instead.
- tools/cpuprof writes samples only at exit (`atexit`): a long run cannot be killed for a partial profile. A test that runs 20+ minutes needs per-step timing first, then a profile of a shorter slice.
- `cpuprof --report` must run from the directory the binary was run from (relative object paths), else every frame is `??`.
- Editing sources while a backgrounded `cargo build`/`cargo test` compiles races: the build may take either version, and a timing run then includes a rebuild.
- The paged harness's `_large` seed 16 runs about 18 minutes in debug (issues/replaced-judgment-cost.md): never put it in a per-branch run without `OSIS_SEED_TIMEOUT_SECS` raised, or it is reported hung.
- Review: measuring main against the branch in one worktree means checking out main and rebuilding the tree (about 5 min each way at load 25); and the load swung 10-53 between the two timed runs, so tier-1 CPU-s compares within about 7%.
