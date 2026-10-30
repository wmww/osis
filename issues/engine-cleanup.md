# Engine module cleanup left over
> Summary: A simplification of osis-engine `engine/` not done: two key-index pruning routines that might be one.
> Tags: engine

No failing test; behaviour-preserving refactors unless noted.

- **Two key-index pruning routines**: `pages::strip_touched` records the touched elements' keys before stripping and removes the rows no longer indexed; `pages::unindex` does the same for dropped bodies from the bodies' own keys. One routine over the bodies would save about ten lines, but touched dots and the bodies' dots differ (removals, `Derived` set elements read as a superset) and a merged one may remove more rows (stored bytes change); only with a randomized differential of the key rows first. Judged not worth it in the engine-cleanup branch. Seen again in mid-cleanup: a shared row-removal helper would save about five lines only, and the two differ where the position is gone after the change (`strip_touched` keeps the rows, `unindex` removes them); checked: a strip keeps stripped writes as value-less records and a delta with a reset or case change above a paged collection takes the whole rewrite, so no position on a paged path goes (`strip_touched_nested_rows_spec_commits_5`).
