# A commit waiting for pages is examined again at every blob stored
> Summary: `reexamine` re-runs `examine` (signature check and a decode of each waiting part) for every durable commit parked under `Wake::Blobs` at each `put_blobs`, though its reach walk still lacks pages; a fill of P pages arriving in B batches costs about P·B page reads. The walk already knows (`reach::lacks`); only memory commits consult it (`still_waits`).
> Priority: normal
> Tags: engine, sync

- Measured: engine `tests_paged::hostile_link_trees_cost_rounds_by_pages_spec_wire_6`, one `examine` and one `examine: signature` per round, the part decoded each time.
- Each decode goes to the first missing page; a full check (`Dec::checking`) then goes on through the held pages of that position's tree for the tree rule (notes/decode-bounds.md, Link trees), so per examine about the held pages of the tree.
- Fix shape: skip a commit whose walk lacks a blob, as `still_waits` does for memory commits, but only for its parts waiting on blobs: a part awaiting a record must still apply when the record comes (each part judged alone, spec/commits.md §4), so the gate is per part, not per commit.
