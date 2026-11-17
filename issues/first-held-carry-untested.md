# Carried re-grant answers are reached by no test
> Summary: A wrong `first_held` answer carried over a timeline's growth (`Kept::carry`, `inserted`, `extend`, `add_leaves`) fails no engine or perm test, though `Timeline::check_first_held` would catch one it is asked about; no test grows a timeline past a re-grant bound it already answered.
> Priority: low
> Tags: tests, perm

Planted with `tools/mutate.py` over the engine lib and `it` and perm `it` default tests (notes/test-harnesses.md, Planted verdict faults), each caught by no test: `carry` keeping an answer at the first change that differs (`p <= b`), `inserted` keeping answers past the insert, `extend` keeping answers on things below a new record or `add_leaves` on new leaves, `carry` keeping answers when nothing is common. A small perm test would do: a node re-granted at change k, its bound asked, then a write placed before k (insert, late arrival mid-history, a new record above the thing), the bound asked again and compared with `Timeline::evaluate` from scratch and with `check_first_held`.
