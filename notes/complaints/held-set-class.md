# held-set-class
- `OSIS_ORDER_SHRINK=1` at plain size takes over an hour per seed on a loaded box, and the shrink drifts to whatever failure it meets first (743309 shrank into a different mechanism). The per-commit index diff against the keep-everything node (`explain`, now under `OSIS_ORDER_DUMP`) found every mechanism faster than shrinking.
- `dump_order` only ran for plain orders; clocked, late-part and held-model failures printed nothing. `explain` runs for all of them.
- testenv refuses unknown `OSIS_*` variables, so a throwaway probe variable must not start with `OSIS_`.
- An engine change rebuilds the node test binary in 4-6 min at load 30+; each probe round cost that.
- Reviewer: each osis-node test rebuild after an engine or crdt edit took 4-8 min at load 40; checking that both new tests fail with their fixes off, then probing one seed, then the fix, cost three of them. A `cargo check -p osis-engine` first catches compile errors in about 1.5 min.
- Reviewer: the held-model "differs" message prints the model's input but not the node's state, so telling which un-merge rule the two read differently meant reading raw `Frag` debug output with 31-byte session sources.
