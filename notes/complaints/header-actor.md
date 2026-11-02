# header-actor
- `wt`/`claudewait` not on PATH in the subagent shell (known); a `claudewait X || <full path> X` fallback ran the wait twice and overran the tool timeout.
- First tier-1 run without `--no-fail-fast` stopped at the first failing crate (osis-commit), hiding the vectors failure until a second 3-minute run; use `--no-fail-fast` when a change may break several crates.
- The brief named spec/api.md; the file is notes/api.md.
