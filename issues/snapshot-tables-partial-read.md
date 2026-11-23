# A partial read of a snapshot loads its whole root tables
> Summary: A snapshot's root tables page (spec/crdt.md §8), but a reader covering only some positions still loads every table page first (`Src`/`Ci` count entries across the pages in link order): about 50 MB at 10^6 commits. Per-page tables would read in proportion to the positions read, at roughly 10-30% more bytes on text and list snapshots and a rewrite of the decoder's table and canonical checks (notes/crdt.md).
> Priority: low
> Tags: crdt, engine
