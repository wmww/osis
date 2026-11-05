# api-shapes-b
- An API change with 1400 call sites: `cargo check --message-format=json` plus a script wrapping each `Ak: ApiKey` span was the only sane way; rustc reports the follow-on method errors as hundreds of noise lines.
- A regex rename of `d.starts_with("Removed")` style checks was the trap: a negative `!any(starts_with(..))` keeps passing when the text changes. Checked by hand.
- `git grep -A8 pattern -- path` needs `-A8` before the pattern, unlike grep: "unable to resolve revision".
- Backticks in a double-quoted bash pattern run a command. Use single quotes.
