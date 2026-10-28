# crdt-text-part
- `cargo fuzz run` leaves `core/test/fuzz/corpus/<target>/` untracked (not gitignored, unlike `artifacts/`); delete it by hand before committing.
- `Partial::misses()` drains: a debug print of the misses inside a Pager loop silently made the loop stop loading.
- Review: `list_edit_on_partial_placement_loads_its_window_spec_5_7` failed at `OSIS_CRDT_SEED=127` (on main too): a threshold, not a bug. A stale base of the same length as the read may rightly take the window; the test now asserts a stale base of another length matches whole and needs 2 such, not 3 stale whole matches.
- Review: a `sed` on an assert line matched a twin assert in the sibling text test; check `git diff` after any pattern edit in the long test files.
