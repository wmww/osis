# review-a1-walk
> Summary: Mishaps met reviewing the rebuilt osis-perm `paths` walk.

- The `paths` `_plain` differentials are `#[ignore]`d, so `cargo test -p osis-perm` runs no differential at all; two of four walk mutations surviving the default tests were caught only by them, two by nothing until new hand worlds. A brief saying "the default tests" for a walk change should say "plus the `_plain` properties".
- `role_paths::new_walk_differs_only_by_design` is by hand, so its "concurrent leaves" class (the removed remaining-admin rule) went stale unseen on the branch that removed the rule.
- A hand world signing as a thing with no listed key (GU) reads differently in model and walk (the key hop is always listed until A4): an easy trap when writing a may-grant world; sign through [A2, GU] instead.
