# role-paths-shift
> Summary: footguns met fixing the role-paths property's shifted timestamps.

- A new `OSIS_PROBE_*` var panics until listed in core/base/testenv-known.txt; reusing the property's existing dump var avoided touching osis-base.
- A passing test's stderr is captured: a dump comparing two runs needs `--nocapture` to show when they agree.
