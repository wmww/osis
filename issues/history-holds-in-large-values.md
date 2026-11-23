# Held history ignores strongs inside large values
> Summary: `refs::kept` reads a held body's strongs with `Fragment::each_value` and stops at a link, so under `history_holds_targets` a strong inside a chunked set element or map key in a held body holds nothing, though spec/data-model.md §8 Held history counts every strong in a held valid body. Fix: read large values as the current-state index does (notes/engine-refs.md, Large values).
> Priority: normal
> Tags: engine, data-model

- Where: `kept::held_strongs` (via `refs::references`, which skips a link's content). The current-state index counts a link's content from its `node/refs links` row (`move_link`, waits on missing blobs, `refs::fetched`).
- Needed: a part's strongs include those of each link's content, read once per link (not per body read: `kept::settle` reads a body again whenever it moves), and a body whose link's chunks are missing gets them counted when they arrive (the arrival must mark the part due, as `fetched` re-notes the state).
- Simplest likely route: key the large-value rows by source and AK alone, as now, and let `kept` take a link's references from that row when one exists, reading otherwise; check whether a body can hold a link no current state reads (a replaced write's large value), which then needs its own row.
- Test: the history-holds closure test (`closure::a_strong_in_held_history_holds_its_target_until_the_body_goes_spec_data_model_8`) with the strong in a chunked element; the refs property's history scan reading large values whole (`get_full` for bodies).
