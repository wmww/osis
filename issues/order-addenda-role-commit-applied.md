# held_set_decides_plain: a role commit applied by the node, not by held-model
> Summary: `order::held_set_decides_plain` fails on main at seed 675321254095 (Addenda emphasis): the node applies a `roles.0`/`secrets.0` commit on a dependent thing that held-model does not.
> Priority: normal
> Tags: tests, engine

- Replay: `OSIS_ORDER_SEED=675321254095 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (fails on 9f9a94418; `OSIS_ORDER_SHRINK=1` shrinks it). Found by the slim-a gate.
- `held-model differs: commit ... (#64) applied: model false, node true; parts [roles.0, secrets.0, secrets.0 on a thing with a mint admin], node misses Some([])`, 44 of 67 commits held, in a random order. Which side is wrong is not settled; near issues/order-addenda-validity.md (also Addenda, the other direction).
