# keel-final-review
- `tools/spec_map.py --gaps` (a gate step) fails on main with 48 stray anchors and 4 untested rules: workers rewording spec do not run it, so the end gate will meet them all at once.
- `cargo test -p held-model`: the crate is `held-model`, not `osis-held-model`; known_failures.txt names the test but not its crate, so replaying a KNOWN line means grepping for it.
