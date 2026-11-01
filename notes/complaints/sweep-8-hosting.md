# sweep-8-hosting
- Agent shells' `grep -rn` (ugrep shim) silently returned nothing for plain patterns in this worktree (`grep -rn 'struct LabelId' core/`); `git grep` worked. Cost a few confused calls.
- `cargo test -p X --lib a b` rejects two filters: they go after `--`.
