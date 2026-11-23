# snapshot-tables
> Summary: workflow notes from paging the snapshot root tables.

- The crdt vectors' hand-built snapshot rejections had six root items, so each was refused for its arity, never for the rule it named; `reject_case` checked only that decoding failed. It now also refuses an arity, frontier or facts error.
- Hand-built `Commits` tables are spread across a dozen crdt test files as nested `l(vec![...])` literals; a wire-format change means a regex sweep. A shared builder (like `testutil::narrowest_facts`) would localize it.
