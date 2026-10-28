# scale-setup
> Summary: workflow mishaps met while cutting the scale timing checks' setup cost.

- wt2's target was 14 GB again at claim (9 GB stale `incremental/`, after the feature-unification branch); `tools/wt claim` warns but still hands it out. Deleted `target/debug/incremental` only (fingerprints stayed fresh, no cold build).
- The issue's figures were stale or from dev builds: at claim, release at 10^4 `late_delta_deaths_cost` took 137 s (not 54 min), `sync_pass_cost` 40 s (not 541-765 s), `text_*` 1-5 s. A dev run of `sync_pass_cost` gives a 524 s first sync, matching notes/testing.md's "545 s": the dev build's `check_unchanged` re-examines every pending commit. Timing figures should name the profile.
- CLAUDE.md still says `tools/slot` and "never `-p`", while notes/build.md and the brief say `tools/wt` and allow `-p`.
- `cargo test` output piped through `grep -v` is block-buffered: a background log shows nothing until the test ends. Use `grep --line-buffered` in run scripts.
- "Blocking waiting for file lock on package cache" several times: other agents' cargo invocations share `~/.cargo`; harmless, a few seconds.
- Review: the release build warned `unused variable: joins` (perm `timeline.rs`, used only under `debug_assertions`); the gate builds dev only, so release-only warnings go unnoticed.
- Review: a dev run with `grep` filtering on the test name hid that `demotion_heavy_open` is a helper called by `membership_change_and_open_cost`, not a test (`--exact` matched nothing, "0 passed" looked like a pass).
