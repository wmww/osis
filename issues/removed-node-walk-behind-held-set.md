# A removed node's client trips the walk-behind-held-set assert
> Summary: osis-account `account::a_removed_node_no_longer_acts_through_its_client_*` panics in the engine: "the walk read behind the held set" (core/engine/src/engine/mod.rs).
> Priority: normal
> Tags: engine, tests

Fails on main every run (seen at 7e751cf01 and later; not yet bisected): `cargo test -p osis-account --test it -- account::a_removed_node_no_longer_acts_through_its_client`. The panic is the engine's own check that a walk read nothing past the held set, so a read on the removed node's path walks a thing it no longer holds. In tools/known_failures.txt against this issue.
