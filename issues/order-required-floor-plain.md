# held_set_decides_plain misses its emphasis floors at some offsets
> Summary: `order::held_set_decides_plain` (8 seeds, order.rs uses no sync engine) fails an emphasis coverage floor at some offsets on main: Purges ("not a permanent delta purged by name and one by author") at `OSIS_ORDER_START=539131766525`; other floors (Settings, Keeps) have flipped at other offsets. At plain size each emphasis gets about one seed, which does not always reach everything its floor names; a floor that flips with the offset fails reviewer sets in every area. Listed in tools/known_failures.txt.
> Priority: normal
> Tags: tests, node

## Direction
Make each emphasis reach what its floor names by construction in each of its seeds, or derive the floor from the seeds it got (notes/coordination.md, Every check runs at every size).
