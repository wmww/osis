# Held-writes pages below seven steps do not split
> Summary: `osis_crdt::PagedRows` keys a page by its first row key cut to `bounds::PAGE_KEY` (120 B: seven 16-byte step hashes and part of an eighth), and never splits rows whose cut keys agree, so every position below one eight-step prefix (a deep text's buckets, a deep map's entries) shares one page: each write there rewrites the whole subtree's held writes.
> Priority: normal
> Tags: engine, performance

## What
Held-writes rows are keyed 0 ‖ a 16-byte hash per step ‖ 16 zero bytes ‖ tag (core/crdt/src/held.rs, module doc), so a key grows 16 B per path step. A page's key is the row key cut to the table key bound (`btree::check_key`: a quarter of the smallest store page, 128 B), less the page tag. Rows agreeing on those 120 bytes stay in one page whatever its size (`row_pages::PagedRows::write`). A position eight or more steps deep (e.g. a text in a record field of a list element inside a map entry inside a list element: Item, In, Field, Entry, In, Item, In, Field, then the text's buckets) puts its whole subtree in one page, so an edit there reads and writes O(subtree), not O(change) (spec/requirements.md, Scale).

## Directions
- Keys whose length is bounded whatever the depth while keeping a subtree a contiguous range (e.g. deeper steps folded into one hash of the path so far, at the cost of `below`'s per-step order there).
- Split such a page by the full row key, with the page key a hash-free prefix plus a sequence number.

No test reaches a path that deep; a scale check (n vs 10n bucket rows under an eight-step path, pages written per edit) belongs with the fix.
