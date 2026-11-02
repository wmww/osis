# A wide purge request with keep-at-most bodies or split commits depends on arrival order
> Summary: A whole-aspect or by-author request with no reset in its commit, mixed into `order::history`, gives states or facts differing by arrival order in about 3% of histories: a differing value-less winner after a body dropped before a validity flip, then purged, and a body known at one node only. Reads were alike where looked at. The chat's own class (permanent bodies) passes.
> Tags: engine, retention, tests

Found on history-read, by mixing `Step::PurgeAuthor` into `order::purge_history`. `PurgeItem::Aspect` in its place fails on the same histories, so it is not the item; main only reaches it rarely, since `Step::Purge` writes the register and names commits.

Repro: in `purge_history`, add `3 => out.push(Step::Aim(Box::new(Step::PurgeAuthor { by: 0, t, of: by })))` to the draw, then `cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_purge_large_spec_commits_5` (default seeds 3000..3060): seeds 3028 and 3050.

- 3028: reg state's winner `value: None` at stamp `..079:8` in made order, `..082:11` reversed. The `..082` body has a keep at most and an invalid write above it: dropped before the flip in made order, `order::flip` tolerates that because the body comes back (`alike_exchanged`), but the purge means it never does, so its residue never joins. A later write stamped between the two would read differently.
- 3050 fails on main as it stands, no by-author step needed: `order::arrival_order_purge_large_spec_commits_5` at its default seeds, seen at 32677c5b (`OSIS_ORDER_SEED=3050 OSIS_ORDER_LEN=60`). With the step: `body (81bf.., t:map.0) known at one node only`, an order with late parts, on a commit with a part on `t:map.0` and one on the purged `t:reg.0`. Not analysed.
- With the step also writing the register, seed 3018 differs on `t:map.0`. Not analysed.

`order::arrival_order_purge_author_*` uses its own history for this reason. Drop that restriction once fixed.
