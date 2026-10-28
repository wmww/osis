# crdt-text-part
- `cargo fuzz run` leaves `core/test/fuzz/corpus/<target>/` untracked (not gitignored, unlike `artifacts/`); delete it by hand before committing.
- `Partial::misses()` drains: a debug print of the misses inside a Pager loop silently made the loop stop loading.
- `list_edit_on_partial_placement_loads_its_window_spec_5_7` fails its threshold at `OSIS_CRDT_SEED=127` on main too (2 stale edits matched whole).
