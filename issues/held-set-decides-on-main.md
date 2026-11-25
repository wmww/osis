# held_set_decides fails on main at three seeds
> Summary: osis-engine `order::held_set_decides_plain` (and `_exhaustive`) fail on main at seeds 532945376429 (PartsAway: `owed_fires` unwraps `Engine::fire_commit`, which is `None` for an owed sealed copy, `Fire::Copy`, though `sealed_fire` returns it), 532945376430 (Settled: after settling a node reads a `t:text.0` as none where the node keeping every body reads "x") and 755979868238 (Settled: the node closure's wait loop passes its bound). Both replay on main; causes not studied past that.
> Priority: normal
> Tags: engine, tests

Found by the spar-review-prep baseline (`tools/gate.sh --all` on origin/main dd5c0a3e4). Replay: `OSIS_ORDER_SEED=<seed> cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain`. Listed in tools/known_failures.txt (rate). Fix each with a hand-written reproducer (notes/principles.md, Never pin a seed).

- **PartsAway** (532945376429, both sizes): `tests/it/order.rs` `owed_fires` takes `fire_commit(&id).unwrap()` for every fire `sealed_fire` returns. A `Fire::Copy` keeps no commit of its own (`flows/inbox.rs` `sealed_fire` builds it from `edge_piece`), so `fire_commit` is `None`. Either `fire_commit` names the copy's commit for a sealed copy, or the harness takes it from the sealed fire; decide by what a receiver's clock check needs (the copy's stamp).
- **Settled** (532945376430, plain): `settled: shows other than the node keeping every body`, `t:text.0` want `Some(Str("x"))`, got `None` at the settled check. Unshrunk (`OSIS_ORDER_SHRINK=1`).
- **Settled, closure wait** (755979868238, plain): on the way to `Order(0, 1)`, `Engine::run (what waits for things entering the node closure): 4 rounds, past its bound of 2 (0 pending)`, progress `[36, 3, 1, 1]`. Found by the kept-unread gate; replays on main 6310c22f6.
