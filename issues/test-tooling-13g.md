# Test tooling from watchdog 13g
> Summary: small tools the last stretch's agents kept rebuilding by hand: a rename-diff token table, `tools/bin-at` with a patch, an on-demand ephemeral sync trace, per-seed timeouts in seed runners, a gate shortcut for docs-only branches. Low; each saves agent time.
> Tags: tests, tools

- `tools/rename-table`: print every renamed token in a diff (`old -> new`, counts) so over-matches (`RELAYS_REMEMBERED -> RELAYS_REHOLDERED`) show at a glance (notes/build.md rename checklist).
- `tools/bin-at REV OUT --patch FILE` (or extra files): build a new test against an old revision; two agents did it with git plumbing.
- An env-switched trace of ephemeral sync keyed by commit (lane decisions, fetches, drops); two agents spent five rebuild rounds on prints.
- Seed runners (`run_seeds_noted` and friends): a per-seed timeout naming the seed that hung (a 300-seed run hung 15+ min silently).
- Gate: a spec/notes/issues-only branch skips tier 1 except the one test that reads notes/ (78 s saved per docs-only branch).
