# paged-dead
- `cargo test -p osis-node --test it retention:: keep::` fails ("unexpected argument 'keep::'"): two filters need `-- retention:: keep::`. CLAUDE.md's form shows one filter only.
- The paged-apply `_large` replay prints its 60 s progress lines only at the end when piped through grep into a file (grep buffers); use `grep --line-buffered` to follow a background run.
