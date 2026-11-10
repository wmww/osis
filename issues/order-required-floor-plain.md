# held_set_decides_plain misses its emphasis floors at some offsets
> Summary: `order::held_set_decides_plain` (8 seeds, order.rs uses no sync engine) fails an emphasis coverage floor at some offsets on main: Required ("not a delta broke a required retention and a setting fell") at `OSIS_ORDER_START=252331946309` (main 40150eb0a), Keeps ("not kept writes on a register, a set and a map, and held-model judging a covered body kept until T") at `436587983156` (main 7f48f91ee). At plain size each emphasis gets about one seed, which does not always reach everything its floor names; a floor that flips with the offset fails reviewer sets in every area.
> Priority: normal
> Tags: tests, node

## Direction
Make each emphasis reach what its floor names by construction in each of its seeds, or derive the floor from the seeds it got (notes/coordination.md, Every check runs at every size). Check against thing-history step 3, which changes what `required^.0` governs (`STEP3_REQUIRED` in held.rs).
