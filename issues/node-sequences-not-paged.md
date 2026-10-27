# Texts and lists load whole in a session
> Summary: An `edit` of a large text or list (what `osis::text` writes), an op at an index segment of a path, and writing a whole collection still load it whole; cold edits write about twice the store bytes they did. Reads by index, local inserts, deletes, moves and pastes, undos, received joins, map keys, set values and struct fields load only their pages.
> Tags: performance, node, storage, crdt

Repro: `cargo test --release --workspace --test it scale::text_ -- --ignored --nocapture` (`text_undo_and_first_access_cost`, `text_range_and_edit_cost`).

Done (notes/node.md, Paged state): collections paged at any depth below struct fields, enum payloads and map entries; lazy loading of the pages a read by key, a write to map keys, fields or set values (the value index), or a join touches; undo footprints by dot (text included); `/secrets` ingestion of the touched entries; body drops, expiry and purge rewrite the touched pages only.

Remaining:
- Sequences (notes/node.md Paged state: the stored placement is the crdt's, held in part; joins, ops by index, undos and whole sessions follow it). Left:
  - `Op::Edit` (what `osis::text` writes: `seq_diff::edit` aligns against the whole read) loads the sequence whole; it would need a diff over the changed region only (the client's old and new values bound it).
  - An index segment in an op's path or in `get_at` (`walk` loads the sequence whole to step into an element); a list element's nested write through the placement held in part would do.
  - Store bytes per cold edit about doubled (insert 12-16 → 28-32 KB, delete 19-23 → 32-38 KB, move 45-50 KB): the block, its dot-map chunk and the top with its group sit in different store units. Keying chunks near their blocks, or folding the map into the block rows, would save one or two units. Measured (10^5 chars after 12 inserts): the placement table is about 37 KB (top and 13 groups 5.5 KB, 391 blocks 16 KB, chunk list 1.8 KB, 317 chunks 14 KB; rows 40-160 B), so 5-6 B+tree leaves of 8 KiB, and an edit rewrites three of them (top with groups, a block, a chunk) where the old layout's placement fit about one. Not a row-size problem: each row is small; the dot map's chunks are sized by entry count (√n), not bytes, so 317 tiny chunks where a few would do.
  - An op whose layered follow (a commit's later op) or placement fails for a reason other than a miss resolves against a whole pass, which over records held in part is a miss of every record (`Partial::whole_pass`): it loads whole. Rare in the crdt tests (a layered follow on the whole state never failed there); the node has no count of it.
  - A move's follow finds each moved subtree's end by depth (`Placement::past`); after many moves depths are uneven and it can read most blocks (still below a whole load).
  - A whole load reads every block and chunk of the stored placement (about a whole pass's cost; first whole read of 10^5 chars unchanged at about 0.13 s).
- Ops whose map keys or set values have struct or map parts load every page (the crdt matches them as the writer's type projects them, which the index cannot see).
- Collections inside list elements or at a `Slots` position (an `any` field written with several kinds) are not paged apart from what holds them: not a small extension (a list element's position needs the sequence's placement and its record's anchors, a `Slots` member the register embedding; osis-crdt work), best done with the sequences item.
- O(aspect state) by nature (notes/node.md, Whole rewrites): a reset of a paged collection or above it, a validity rebuild, a page or skeleton outgrowing `PAGE_TARGET` (once, re-laid out).
