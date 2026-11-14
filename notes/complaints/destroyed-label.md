# destroyed-label
- The brief's scratch pointed at a shared scratchpad root crowded with hundreds of other tasks' files; a redirect to a not-yet-made task dir silently ran nothing (the background job "succeeded" writing nowhere).
- `GroupLabel` lives in a private `labeling::actors` module, so engine code outside it that wants to build one from a `label.0` value needs the module opened `pub(crate)`.
- Review: a `git checkout --detach` typed in the main checkout instead of the worktree moved main's HEAD silently; the main checkout should refuse branch moves.
