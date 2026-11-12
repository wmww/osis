# cover-once-quiet
- Checking a fix by disabling it: turning off only the quiet term of `fire` still left the forced quiet weighing, which fires on the cost test too (churn writers' leftovers weighed past `FACTOR` at the quiet time, never re-weighed since their expiry), so both seeds passed "without" the rule. Disable the whole mechanism, not one condition.
- `cargo test -p osis-node --test it quiet ephemeral::x` fails (cargo takes one filter before `--`); pass filters after `--`.
- Reviewer: a churn replay with `eprintln!` probes prints nothing unless `--nocapture` follows `--`; the harness passes and hides stderr.
