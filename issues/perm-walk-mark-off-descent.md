# osis-perm's walk applies a write roles-model reads off a descent
> Summary: perm hand world `paths::hand::a_mark_off_a_descent_of_two_steps_applies_nowhere` (ignored) fails on the rebuilt walk: A's content on T1 stated by the descent [] (delta 4) the model reads invalid, the walk valid; cause not studied.
> Priority: normal
> Tags: perm, tests

Replay: `cargo test -p osis-perm --test it -- --ignored --exact paths::hand::a_mark_off_a_descent_of_two_steps_applies_nowhere` ("delta 4: model valid false, walk Some(Valid(Held))"). The rule is draft §1 Path, Direct mark (the one-encoding rule); the model's counterpart of the same name passes. First check whether it is the key hop (A writing as itself: issues/perm-walk-trails-model.md) or the walk's reading of marks.
