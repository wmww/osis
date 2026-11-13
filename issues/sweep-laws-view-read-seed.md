# sweep_laws: a stale view's sweep changes its read
> Summary: `tests_life::sweep_laws_spec_sync_7` fails on main at `OSIS_CRDT_SEED` 917311 and 77310519: joining a view's own sweep changes the view's read (`Some(Map({}))` against `Some(Map({0: List([0])}))`), so the sweep took something still shown.
> Priority: normal
> Tags: crdt, tests

Reproduce: `OSIS_CRDT_SEED=917311 cargo test -p osis-crdt --lib -- sweep_laws` (effective seed 1617995461732687361, committed 3; assertion "the view's read", tests_life.rs). Next: shrink to a hand-written case and check it against the sweep rule (notes/crdt.md, Hidden writes go by a sweep).
