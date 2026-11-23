# The reference index reads a large value with full depth room
> Summary: `large::link_references` reads every link within `MAX_VALUE_DEPTH` levels, whatever its position, so a link nested deeper than its position leaves room for (spec/data-model.md §5, §6: it reads as absent) still counts its content's references (state and held history alike); a hostile writer can make the index hold a target no read shows.
> Priority: low
> Tags: engine, data-model

- Honest writers never produce one: the writer refuses a value deeper than `MAX_VALUE_DEPTH` as read (`out_of_profile`, before chunking). Reaching it needs a link placed at a deeper position than it was made for (a hand-built delta, or an app handing a `Value::Link` into a deeper op if the write path takes one: check first).
- Fix shape: positions carry their read depth. `Fragment::values_with` passes each value's depth as read (struct field and map key/value +1, set element and enum payload +2, list item +1, as `Value::depth` counts); a depth-aware `Value::each_reference_or_link` gives each link's depth inside a value; a link's room is `MAX_VALUE_DEPTH − depth`. The `node/refs links` key and `Delta`'s link map take (hash, room), since equal content at two depths reads differently; `kept::Part` links likewise; `references_below` gives an inner link the room left at its own depth inside the content (it uses `room − 1` now), its memo keyed by (hash, room).
- Test: such a link at a reader holds no row and no history strong, its target not held; the same content at a shallow position counts.
