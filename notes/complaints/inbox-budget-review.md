# inbox-budget review complaints
> Summary: Mishaps met while reviewing the inbox deposit budget.

- A foreground `cargo test -p osis-node` hit the tool's 180 s move while a rebuild ran (load about 20); cost nothing but a claudewait.
- The brief's `tied::` oracle lives in `core/osis` (`-p osis`); my first run with `-p osis-node` said 0 passed, exit 0.
- First wake test passed with the wake off: `create_label` delivers its own inbox blob, which copies by itself. Spot-checking the test found it.
