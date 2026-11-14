# Complaints: capstan-integrator
> Summary: footguns met merging module branches into sync-rebuild.

- git rerere is on for the shared repo: a resolution recorded on one rebase was replayed on another branch's different conflict (wrong flows.rs and facade note text). Rebase with `git -c rerere.enabled=false`.
- Union-resolving two tests appended at the same spot drops the closing brace both sides share (three times): after a "both" resolution, check that the earlier block still ends in `}`.
- A worker's commit made in a worktree whose branch moved under it (parent 2e9d00548, tree from 1d36c54e8) reverted 37 files of another branch; check `git show --stat` of each commit before a fast-forward.
- Main's test anchors predate spec_map's stray-anchor check: every merge of main needs the anchors renamed to rule names.
