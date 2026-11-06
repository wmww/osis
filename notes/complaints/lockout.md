# lockout complaints
- An invariant of the form `CanRemove \/ \A e \in Blocking : ...` was vacuous whenever `Blocking` was empty, so the `L_none` negative control silently passed and ran for minutes before I noticed. Negative controls catch this only if run first.
- An unguarded Reseal action grew `L_list` from 3.8M to 19.7M states (11 min): guard model actions to the configs that need them before sizing runs.
- Review: `rotate_boxing_only` after `spread_sealed` (the vandal holding a holder actor of its own) failed `Permission` where `spread` did not; unexplained, worked around in the test.
