# grant-frontier
> Summary: footguns met while giving auditing grants a frontier.

- `cargo test -p X --test it a:: b::` without `--` fails with a cargo usage error (the second filter is taken as a cargo arg); easy to misread as a test result when grepping.
- Many node tests hand-write demotions as raw `roles.0` mutations with no frontier, so a writer rule requiring one on auditing grants broke tier 1 in six places; the rule was dropped rather than teach every helper the edge as restored.
- The audit trigger counted any `until` as lowering, though it can drop nothing at R; making the frontier follow "audits" then broke every timed demotion in rotation tests. Check a predicate's vacuous cases before reusing it for a wire rule.
