# review-order-fails
> Summary: Footguns met reviewing order-fails.

- `cargo test -p osis-engine` piped through `rg` in the background reports rg's exit; the `test result` lines were the only check (as CLAUDE.md says), easy to miss when the exit reads 0.
