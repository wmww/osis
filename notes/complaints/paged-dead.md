# paged-dead
- `cargo test -p osis-node --test it retention:: keep::` fails ("unexpected argument 'keep::'"): two filters need `-- retention:: keep::`. CLAUDE.md's form shows one filter only.
- The paged-apply `_large` replay prints its 60 s progress lines only at the end when piped through grep into a file (grep buffers); use `grep --line-buffered` to follow a background run.
- Review: `git rebase main` conflicted on issues/paged-apply-dead-writes.md (main edited it, the branch deleted it); notes/test-design.md still listed it as open.
- Rebase check: paged-apply seed 16 (default range) passes only after 667 s, past the 600 CPU-s hung limit, on main too; a 24-seed default run takes about 20 min, so "run the default range" is not a quick check.
