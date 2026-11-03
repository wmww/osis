# An import's body never reads as live
> Summary: `retention::live` judges a body by `Owned::of`, which for an import names its empty range, so `body_live` says false while the state reads its writes (seen: read `Some("bob's")`, `body_live` false). spec/commits.md §5 counts any write the state holds by dot, and an import holds origin dots.
> Tags: engine, retention

Effect: an import under a keep at most loses its grace, and under at most 0 drops at its first death with live writes left and no carrier; a device coming later may read less. `sync::pass::delete::part_live` reads the same answer.

Fix to weigh: judge by `retention::writes_of` in `live` (and its oracle twin), and have `part_live` use the same list check (`gone_of`), since a value-less write is held by dot too.
