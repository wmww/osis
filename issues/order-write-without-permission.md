# held_set_decides_plain: a generated write the node may not make
> Summary: `OSIS_ORDER_SEED=523958221486 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` fails on main 9907839a3 at order.rs:955: a write the harness expected to fail `BadInput` failed `Local` ("no permission to write"). Either the generator's permission model and the engine disagree on who may write, or the harness expects the wrong error kind. Shrink with `OSIS_ORDER_SHRINK=1`.
> Priority: normal
> Tags: tests, node
