# held_set_decides_plain misses its Required floor at some offsets
> Summary: `order::held_set_decides_plain` at `OSIS_ORDER_START=252331946309` (8 seeds) fails its coverage floor "Required seeds ran, but not a delta broke a required retention and a setting fell" on main 40150eb0a (order.rs uses no sync engine). At plain size the Required emphasis gets about one seed, which does not always reach both; a floor that flips with the offset fails reviewer sets in every area.
> Priority: normal
> Tags: tests, node

## Direction
Make the Required emphasis reach a broken required retention and a fallen setting by construction in each of its seeds, or derive the floor from the seeds it got (notes/coordination.md, Every check runs at every size). Check against thing-history step 3, which changes what `required^.0` governs (`STEP3_REQUIRED` in held.rs).
