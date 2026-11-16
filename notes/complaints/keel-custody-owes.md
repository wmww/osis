# keel-custody-owes
- The custody differential's t-custody check read `trot_epoch`, filled from `ix.secrets`'s `newest_held()`, which is never set for t: the check never ran, silently. A check that can't fire should fail loudly (assert the map fills when t is re-keyed).
- `tail -60` on a failing differential run cuts the panic line (the mirror dump is longer): grep `panicked:` from a full log instead.
- Toggling fixes off to prove a hand test fails before the fix, without `git stash`, took several copy-back dances; a wip commit plus `git diff` reverse-apply would have been cleaner.
