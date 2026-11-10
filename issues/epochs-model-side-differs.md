# epochs_model_agrees: perm sees an epoch the side model does not
> Summary: osis-perm `epochs::epochs_model_agrees_large` fails at small size on `OSIS_PERM_SEED=552768205036` (shard seed 0x980ed607eed, sample 1679): for observer n1 the side model gives no epoch, perm gives `Some(8)`. Deterministic; not root-caused or shrunk.
> Priority: normal
> Tags: tests, perm, keys

Found by the gate-shape branch's measured gate (a branch that changed no perm code: comments only), so main fails it too.

Replay (about 15 s): `OSIS_PERM_SEED=552768205036 cargo test -p osis-perm --test it -- --ignored --exact epochs::epochs_model_agrees_large`. The panic prints the whole `World` (4 people, 5 nodes, one thing, node 1 left at 4 and node 2 at 7, a rotation among the items).

Next: shrink the world by hand to the smallest one that differs, decide which side is wrong against spec/permissions.md §5.5 (the property the test cites), and add the minimal world as a default test.
