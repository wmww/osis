# keel-diff-rest
- `OSIS_SYNC_SHRINK=1` shrinks toward any failure, so a seed failing two ways shrinks to the other one (seed 6's must-hold check shrank to a model mismatch twice). Shrinking by hand with a `catch_unwind` predicate on the message worked; a pattern knob on the shrinker would save that.
- `World::run`'s quiet check (`unreached_must_holds`) fires before `check` compares values, so a reader that reads nothing shows up as a must-hold loss: read the values too before blaming the check.
- `cargo test -p osis-sync --test it a b` refuses two filters; `-- a b` takes them.
