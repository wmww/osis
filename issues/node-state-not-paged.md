# Large states paged only at the aspect root
> Summary: The node pages a large root map, set, bag, list or text (one entry edit at 10^6 keys: 1.1 ms, 54 KB written); a large collection nested in a struct field or map entry (a `/secrets` box map of a big roster), a sequence's undo buffer, and the first load of a paged state per session are still O(state).
> Tags: performance, node, storage

Done (notes/node.md, Paged state): root collections above `PAGE_TARGET` live as ~8 KB pages of consecutive elements in aspect table 0; a join rewrites the pages holding the delta's root dots; joins are in place; the undo buffer keeps `Fragment::footprint`; `Core::invalid` keeps un-merge O(invalid parts); `Engine::get_at` reads one key in O(log n).

Remaining (spec/requirements.md, Scale):
- Nested collections: a struct root whose field is a big map (`/secrets` boxes of thousands of members: a re-seal adding one box rewrites the whole ~2.7 MB state). Shape: page per (field path, dot range), the page index keyed by path.
- Sequence undo buffer: `footprint` keeps a sequence whole (its undo reads by position); a footprint by dot (the delta's elements plus their anchors) would need `seq::undo` to read by dot.
- First access per session loads every page into memory (O(state) once); a lazy in-memory page cache would need crdt ops over partial states.
- Whole rewrites stay O(state) by nature: a root reset, a rebuild after validity flips, retention drops (`set_state`).
