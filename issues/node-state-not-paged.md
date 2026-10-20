# Large states paged only at the root and in root struct fields
> Summary: The node pages a large root collection and large collection fields of a root struct (one entry edit at 10^6 keys: 1.1–1.9 ms, about 50 KB written; a `/secrets` write at a 1000-member roster 19 KB); deeper collections, a sequence's undo buffer, the first load of a paged state per session and `/secrets` ingestion are still O(state).
> Tags: performance, node, storage

Done (notes/node.md, Paged state): root collections, and collection fields of a root struct, above `PAGE_TARGET` live as ~8 KB pages of consecutive elements in aspect table 0; a join rewrites the pages holding the delta's root dots; joins are in place; the undo buffer keeps `Fragment::footprint`; `Core::invalid` keeps un-merge O(invalid parts); `Engine::get_at` reads one key in O(log n).

Remaining (spec/requirements.md, Scale):
- Deeper collections: a big map inside a map entry or a nested struct (the slot is only root or a root field). Shape: slots keyed by path.
- `/secrets` CPU: `observe_state` reads the whole value and `ingest_secrets` walks every box on each `/secrets` change (59 ms at 1000 members, linear); it should look only at the delta's entries.
- Sequence undo buffer: `footprint` keeps a sequence whole (its undo reads by position); a footprint by dot (the delta's elements plus their anchors) would need `seq::undo` to read by dot.
- First access per session loads every page into memory (O(state) once); a lazy in-memory page cache would need crdt ops over partial states.
- Whole rewrites stay O(state) by nature: a root reset, a rebuild after validity flips, retention drops (`set_state`).
