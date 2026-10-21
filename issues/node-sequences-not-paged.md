# Texts and lists load whole in a session; set ops by value load every page
> Summary: The first edit or read of a large text or list in a session loads all of it (about 0.2 s for 10^5 characters), and adding or removing a set element by value, or writing a whole collection, loads every page of a large state. Map keys, struct fields and joins of received changes load only their pages.
> Tags: performance, node, storage, crdt

Repro: `cargo test --release -p osis-node --test scale -- --ignored --nocapture text_undo_and_first_access_cost`.

Done (notes/node.md, Paged state): collections paged at any depth below struct fields, enum payloads and map entries; lazy loading of the pages a read by key, a write to map keys or fields, or a join touches; undo footprints by dot (text included); `/secrets` ingestion of the touched entries; body drops, expiry and purge rewrite the touched pages only.

Remaining:
- Sequences: any op needs the placement of the whole sequence (`seq_lin`), so a paged text or list loads every page; a read by index has no `dot -> position` index (notes/local-store.md planned one, paged as a tree).
- Set ops by value (`Op::Add`, `Op::Remove` on a set) find elements by value and load every page; a value index like the map key index would do.
- Collections inside list elements or at a `Slots` position (an `any` field written with several kinds) are not paged apart from what holds them.
- O(aspect state) by nature (notes/node.md, Whole rewrites): a reset of a paged collection or above it, a validity rebuild, a page or skeleton outgrowing `PAGE_TARGET` (once, re-laid out).
