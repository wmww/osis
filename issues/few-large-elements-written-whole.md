# A collection of few large elements is written whole
> Summary: A collection pages only from `MIN_PAGED` (64) elements, so a map or set of up to 63 elements of any size (up to the 128 KiB chunk threshold each) is rewritten whole at each write: a write there costs O(collection), not O(change). `MIN_PAGED` 2 exposes a read that writes (`Engine::read changed ["written"]`).
> Priority: normal
> Tags: engine, performance

- What it costs: `roles.0` (a map keyed by holder, a tombstone per ended entry) and any app map of a few fat entries rewrite every entry at each write (notes/role-timeline.md).
- `MIN_PAGED` has no stated reason: at 1 or 2 a collection above a page pages its elements one or a few per page, which costs a row each, no more. Tried at 2 (`engine/pages.rs`): `encodings::range_under_removed_key_absent_spec_crdt_5_6` fails `Engine::read changed ["written"]` (a read through a lazily loaded paged state notes it written: a latent bug any paged shape that test builds would hit), and `apply::tests_paged::{reset_drops_dead_paged_collection_spec_crdt_8, entry_creation_after_its_paged_content_spec_crdt_5_6}` fail their asserted shape (`ENTRIES` there is `2 * MIN_PAGED`; pin it at 128).
- Fix: find the read that writes, then drop `MIN_PAGED` to the least that splits (2), or remove it.
