# A paged map's join counts references without the same-key records on other pages
> Summary: the reference index counts a map key as its live records' join (`Fragment::each_read_value`), and a join's reach takes every record sharing a key with those it reaches (`Fragment::reach`, `reach_after`); in a paged map the join loads only the pages of the delta's dots (`Fragment::touched_elems`), so a same-key record on another page is outside the reach and a write into a key whose read another record decides moves rows the read does not show.
> Priority: normal
> Tags: engine, crdt

Reached only by a paged map (one past a page, notes/engine-paged.md) holding two live records of one key on different pages: concurrent puts of one key, or a value of another shape put at a live key. An unpaged state, a whole write (`Tx::set_state`, every rebuild) and a paged reset (`pages::join_reset`, pages whole) count right.

Fix direction: the touch of a map delta loads the records of its keys too (a key index for paged maps, as sets load a tid's records by value, notes/crdt.md `PagedTouch::tids`), so `touched_elems` and `reach` take the same records. Test: R2's generator with a paged map (`known_references_are_a_scan_of_held_values_spec_data_model_8` pages only a list), or an engine example writing into one of two same-key records on different pages.
