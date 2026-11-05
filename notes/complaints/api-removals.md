# api-removals
- A scripted port of a method name hits app helpers of the same name: `Data::get` (a stale workaround of an issue already closed) took the `db.get` port too. Read the consumers' own helpers first.
- `git grep -A` must come before the pattern; two lookups came back `fatal` and looked like empty results at a glance.
