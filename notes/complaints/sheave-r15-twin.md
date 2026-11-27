# sheave-r15-twin
> Summary: an index-check failure in the sync differential does not name which engine copy failed.

`check_index`'s panic ("rebuilt from the commit records ... the index Table(...)") names neither the node nor the twin, so finding which of a world's copies diverged took a probe build printing `osis_base::trace::copy()` at each writer. The message should carry `osis_base::trace::copy()` (the harness already names every copy).
