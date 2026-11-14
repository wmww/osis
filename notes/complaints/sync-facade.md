# sync-facade complaints
> Summary: Workflow snags met building the engine facade for sync.

- Three coordinator course changes mid-task (per-key values, removal epoch, opens' needs) each with a rebase onto a moved sync-rebuild; a module owner adding the same osis-label/crypto items (removal signatures) in parallel made identical-purpose code conflict. Name shared wire items' owner up front.
- `wt claim` had already run (worktree given detached at the base); the preamble's `git rebase --onto sync-rebuild e476f2149` is wrong after the first rebase (the upstream is the previous sync-rebuild tip).
- A python `s.index(a) .. s.index(b)` cut where `b` occurs earlier duplicated half of engine/mod.rs: anchor the end search after the start.
