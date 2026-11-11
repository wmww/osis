# perm-paths complaints
- Any `OSIS_*` env var not in core/base/testenv-known.txt panics every test that reads the env: a temporary probe variable must not start with `OSIS_`.
- `commits_walked` counts walk steps only: the O(history) per-arrival copies (`WalkWas::of`, the shadow's undo-log rebuild) are invisible to every counted scale test.
