# held-order-seed
- The issue's replay (`OSIS_HELD_SEEDS=1 ... _large`) also fails `settled_histories_keep_their_laws_large` on its "no signal dropped past its bound" floor: an aggregate floor that one seed cannot meet (notes/coordination.md: every check runs at every size). Use a `props::<name>_large` filter for one-seed replays.
- The arrival-order failure prints every differing body with `{:#?}`: about 80 lines for one register write. A compact one-line-per-body dump would have saved a debug test.
- Review: the branch deleted the seed's issue but left its tools/known_failures.txt line, so the first gate stopped at policy.py. Deleting a fixed issue means grepping tools/ too.
