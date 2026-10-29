# eph-cover-absorb
> Summary: Minor footguns met on this branch.

- Unit tests in `src/` must cite a spec section in their name too (`tools/spec_map.py --uncited`); only the gate says so, after a full first run.
- `osis_base::TID_LEN` is not reachable from other crates; tests write `[n; 15]`.
