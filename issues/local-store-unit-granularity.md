# Local store unit granularity
> Summary: One encrypted unit per aspect makes every write re-encrypt the whole aspect state, O(map) for a million-key map, violating the scale requirement. Large states need paged units. Must close before the MVP.
> Tags: local-store

Page large states into units of their own (pages of a prolly-tree-like structure, so a write touches one page plus its key path), matching snapshot paging (spec/crdt.md §8). Decide the page structure together with the storage layer. Mechanism context: notes/local-store.md.
