# self-removal-crash
- `wt claim` printed wt1 while the session's environment said wt2; easy to work in the wrong tree.
- `git checkout main -- <src>` for a fix-disabled probe pulled in other branches' newer main code (compile errors); use `HEAD~1` / the merge base.
- Grepping `core/node/src/sync/*.rs` misses `sync/pass/`; I nearly deleted the `first` field as dead. Use `-r`.
