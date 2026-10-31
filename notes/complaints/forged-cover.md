# forged-cover
- The forged-snapshot tests encode the snapshot-copy rule in many places (validity.rs has a dozen); changing the rule meant reading each to tell expected-semantics changes from regressions. A short comment per test naming the rule it pins (held original vs never received vs dropped) would have helped.
- `changed()` ties at the same wall ms (min(ts, received)) silently pick the older commit: a new test asserting the last change needed an `advance` first.
- Squashing wip commits with `git reset --soft main` after main moved would have reverted the new main commits; reset to the branch's merge base instead.
