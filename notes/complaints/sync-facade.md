# sync-facade complaints
> Summary: Workflow snags met building the engine facade for sync.

- Three coordinator course changes mid-task (per-key values, removal epoch, opens' needs) each with a rebase onto a moved sync-rebuild; a module owner adding the same osis-label/crypto items (removal signatures) in parallel made identical-purpose code conflict. Name shared wire items' owner up front.
- `wt claim` had already run (worktree given detached at the base); the preamble's `git rebase --onto sync-rebuild e476f2149` is wrong after the first rebase (the upstream is the previous sync-rebuild tip).
- A python `s.index(a) .. s.index(b)` cut where `b` occurs earlier duplicated half of engine/mod.rs: anchor the end search after the start.
- Review: `tools/bin-at REV OUT -p osis-vectors` fails ("no executable for osis-vectors --test it"): the crate's test target is `vectors`, so `--test vectors` is needed; the error does not say which targets exist.
- Review: sync-rebuild moved during the review (sync-read merged); its tests build facade structs literally, so the rebase compiled nothing in osis-sync's tests until `..Default::default()` was added. Tests outside the engine building facade value types could use a constructor or Default.
