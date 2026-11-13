# tooling-gate-base
- Not fixed, larger than a passing fix: `tools/bin-at` builds only test binaries (a `--bin NAME` would make main's `osis` binary deliberate, cleanup-cli); a comment-only Cargo.toml edit selects every crate plus unification (prose-testing); no `tools/src-at` for library differentials (cleanup-schema); `wt claim` without a base branches from lagging local main (tooling-footguns; the wt plugin, not this repo).
- CLAUDE.md still says the reviewer gates "after `git rebase main`"; it should say origin/main (Tess's file).
