# link-follow
- A cargo test name filter is a substring: `a_joiner_who` also ran `a_joiner_whose_link_…`, and their interleaved probe output read as one test's for a while. Use `-- --exact` when probing one test.
- In the hostless sim shape a leaver stays `leaving` for good (issues/leaving-not-confirmed-after-rotation.md), so any "after a leave" check there needs a host.
- Review: the tier-2 networking command with `--no-fail-fast` prints about 40 `0 passed` lines for crates it filters out; grep `FAILED|panicked` rather than reading the result lines.
