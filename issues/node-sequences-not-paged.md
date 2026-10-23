# Texts and lists load whole in a session
> Summary: The first edit or read of a large text or list in a session loads all of it (about 0.2 s for 10^5 characters), and writing a whole collection loads every page of a large state. Map keys, set values, struct fields and joins of received changes load only their pages.
> Tags: performance, node, storage, crdt

Repro: `cargo test --release -p osis-node --test it scale::text_undo_and_first_access_cost -- --ignored --nocapture`.

Done (notes/node.md, Paged state): collections paged at any depth below struct fields, enum payloads and map entries; lazy loading of the pages a read by key, a write to map keys, fields or set values (the value index), or a join touches; undo footprints by dot (text included); `/secrets` ingestion of the touched entries; body drops, expiry and purge rewrite the touched pages only.

Remaining:
- Sequences: any op needs the placement of the whole sequence (`seq_lin`), so a paged text or list loads every page; a read by index has no `dot -> position` index (notes/local-store.md planned one, paged as a tree).
- Ops whose map keys or set values have struct or map parts load every page (the crdt matches them as the writer's type projects them, which the index cannot see).
- Collections inside list elements or at a `Slots` position (an `any` field written with several kinds) are not paged apart from what holds them: not a small extension (a list element's position needs the sequence's placement and its record's anchors, a `Slots` member the register embedding; osis-crdt work), best done with the sequences item.
- O(aspect state) by nature (notes/node.md, Whole rewrites): a reset of a paged collection or above it, a validity rebuild, a page or skeleton outgrowing `PAGE_TARGET` (once, re-laid out).
