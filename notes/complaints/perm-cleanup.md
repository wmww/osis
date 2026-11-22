# perm-cleanup
> Summary: Mishaps met sweeping "team" and consolidating osis-perm's tests.

- `tools/mutate.py` refuses an OLD of a method chain whose NEW changes the iterator type (`.take(0)`): plant a value of the same type at the receiver instead (`Vec::<Tid>::new().into_iter()`).
- A `tools/icount ... <module>::` filter is a substring: `content::` also counts `paths::content::`; measure top-level modules with `--skip paths::`.
- The ignore reason on `paths::hand::a_mark_off_a_descent_of_two_steps_applies_nowhere` named a step that had landed while the test still failed; ignore reasons naming a plan step go stale unseen (now an issue).
