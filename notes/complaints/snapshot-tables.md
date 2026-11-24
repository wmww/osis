# snapshot-tables
> Summary: workflow notes from paging the snapshot root tables.

- Hand-built `Commits` tables are spread across a dozen crdt test files as nested `l(vec![...])` literals; a wire-format change means a regex sweep. A shared builder (like `testutil::narrowest_facts`) would localize it.
