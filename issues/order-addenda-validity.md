# held_set_decides_plain: an Addenda history judged valid by held-model, invalid by the node
> Summary: `order::held_set_decides_plain` fails on main at seed 817700046039 (Addenda emphasis): with every commit held, in reverse order, held-model judges a `t:reg.0` write valid and the node invalid.
> Priority: normal
> Tags: tests, engine

- Replay: `OSIS_ORDER_SEED=817700046039 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (fails on d3d7c2cf5; `OSIS_ORDER_SHRINK=1` shrinks it). Found by an `--all` gate at offset 817700046035.
- `differs: validity of commit ... (#42) on ... t:reg.0: model Some(true), node Some(false)`, the node's roster holding only the thing's admin edge. The history demotes node 1 (`Demote { by: 0, holder: 1 }`) and re-grants it write from node 2 under addenda (`Cfg { addenda: true, .. }`): which side is wrong (the node's addenda reading or held-model's gaps rule, issues/s3-addenda-build.md item 2) is not settled.
