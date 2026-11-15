# refusals-lift
- The store-wide repro in the issue I was handed could not refuse: give-way evicts any non-role entry, and role entries count toward no cap, so a total refusal needs an entry larger than the total. Repros written without running them cost a round of debugging.
- `cargo test -p X --test it a b` rejects a second filter; several filters go after `--`.
- (review) spec_map rejects an anchor whose quoted piece wraps across a comment line break (the double space it joins with is no text of the spec).
