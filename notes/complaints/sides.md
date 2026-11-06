# sides
- `Engine::create` does not go through `reload`, so a hook put at `reload`'s end (dispute detection on) silently missed every freshly created engine; the node tests found it, after a probe round. One "store loaded" hook for both would have saved a build cycle.
- At load 30-40 every engine change cost a 3-5 min rebuild of the node test binary before one test could run; six such cycles for this task.
- Model search with `--release` for roles-model builds a release artifact set of its deps in the worktree (small: osis-base), the debug search is slower by about 10x.
- Review: at load 25 building the node, osis and chat test binaries after a perm+engine change took 13 min before three short tests could run.
