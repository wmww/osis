# A wide purge request with keep-at-most bodies or split commits depends on arrival order
> Summary: A by-author or whole-aspect request with no reset, mixed into `order::history`, differs by arrival order in about 0.4% of histories (2 of 500; 3% was two seeds of 60): a differing value-less winner after a body dropped before a validity flip, then purged. Reads alike. The chat's class (permanent bodies, hostile writes too) passes. Mostly gone with purge-rejudge: see below.
> Tags: engine, retention, tests

Found on history-read, by mixing `Step::PurgeAuthor` into `order::purge_history`. `PurgeItem::Aspect` in its place fails on the same histories, so it is not the item; main only reaches it rarely, since `Step::Purge` writes the register and names commits.

Repro: in `purge_history`, add `3 => out.push(Step::Aim(Box::new(Step::PurgeAuthor { by: 0, t, of: by })))` to the draw (`3 | 4 | 5` for more), then `OSIS_ORDER_START=3000 OSIS_ORDER_SEEDS=500 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_purge_large_spec_commits_5`.

- 3028, and 5094 with `3 | 4 | 5` (1 of 300 from 5000): one cause. State winner `value: None` on the purged register at differing stamps. The later body has a keep at most with an invalid write above it: dropped before the flip in one order (`order::flip` tolerates that: the body comes back, `alike_exchanged`), and the purge means it never does, so its residue never joins. A later write stamped between the two would read differently.
- 3050, no by-author step needed: `body (.., t:map.0) known at one node only`, an order with late parts, on a commit with a part on `t:map.0` and one on the purged `t:reg.0`. Another cause; a default seed of the oracle, failing on this branch and, by its worker, on main.

With purge-rejudge merged: 3028 and 3050 pass. 3265 (a dropped snapshot's `gives`) and 872030 (a value-less winner) were one cause, a purge standing, falling and another rising over a part with no copy left, the residue half fixed by the row kept through the fall; a dropped snapshot's `gives` after a rise is now a stated limit (spec/permissions.md §8); 5094's mix not rerun. With the step also writing the register, seed 3018 differs on `t:map.0` (seen by the worker, not analysed).

Why only `Step::Purge`-free mixes hit it: `Step::Purge` writes the register and names commits, so the winner is that reset. `PurgeItem::Aspect` in the step's place fails on the same histories, so it is not the item.

`order::arrival_order_purge_author_*` uses its own history for this reason: permanent messages, no keep at most. It also passes with `Breaking`, `Require` and `Forged` mixed in (150 seeds from 8000), so what a hostile member does in a chat is covered in fact, though not in the default mix. Drop the restriction once fixed.

Seed 106342 of `order::arrival_order_alike_large_spec_permissions_5_2` (`OSIS_ORDER_SEED=106342 OSIS_ORDER_LEN=60`, about 3 min) fails on main at 2964db75 with no purge step: after bodies dropped before a flip were given again, one commit reads `missing: {1}` as made and `dropped: {1}` in another order. Likely the same family as 3265; not analysed.

A narrower mix, keep at most or a required retention on the purged register with requests by name, falls and compactions (a register write with keep at most drawn into `order::purge_rows_history`, 1200 seeds from 8000): 7 of 300 keep-at-most histories and 1 of 300 required ones differ, on death dates of bounded bodies and on whether a bounded snapshot is dropped. The row is not shown to cause them: in a wider mix (800 seeds from 7100) the same 15 seeds failed with the previous `wl/` code, though the row's join ran in some of them; some shrink to no purge at all (keep-at-most and expiring writes on one register, seed 7228 of that mix). Not analysed; bounded bodies under a raced demotion, so it stays a stated limit unless a common flow meets it.
