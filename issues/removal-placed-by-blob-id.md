# A removal is logged after the content beside it when the content's blob ID is lower
> Summary: spec/permissions.md §3 places a removal before the content written beside it under every label, but node-sync stamps (and so logs) a pass's own entries in blob ID order and the host's log follows a blob ID order too: `sync_more::removal_placed_first_under_every_label_spec_perm_3` passes on main only by the IDs its seeds draw.
> Priority: normal
> Tags: sync, node-sync, tests

- Found when chunk-tree-4 changed the header bytes (every commit and blob ID moved): the test fails there at default seeds and at seeds 4, 5, 6, and passes at 11, 12, 13; main passes at its default seeds and at 4, 5, 6, where the removal's blob ID happens to sort first.
- Trace (a `set_entry` print): the pass places the removal first (`body_sends` orders by `prio`), then stamps its own new entries in the `cands` loop of `pass/mod.rs` (after `local_promote`), a `BTreeSet<BlobId>`, so the lower blob ID is stamped and logged first.
- Sorting that loop by the sends' priority fixes the node's own log order (tried), yet the host still logged the content first: another step on the way to the host (the stream serving the node log, or the host storing what it pulls) orders by blob ID. Not found.
- Fix: every step from placement to the host's log keeps the pass's order (role commits and requests, then the rest); a test that varies the seeds (or the blob IDs) so it cannot pass by luck.
