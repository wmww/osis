# list-cuts-review
> Summary: Mishaps and slow spots met reviewing the list-cuts branch.

- `dump::paths_dump_readings` hashes whole readings per world, so a moved line says nothing of what moved; and a generator change (the soups now draw a thing per list entry) moves every soup line. Comparing the model's `judge` under the rule and its control over the dump's worlds, printing each moved delta's path and edge writes, was what classified the moves.
- `#![forbid(unsafe_code)]` in the perm tests rules out `std::env::set_var` for a probe toggle; a `pub static AtomicBool` in the model works.
- Purge worlds' stats print nowhere in the default or gate runs unless a test calls `PStats::print`; noted (excused) counts were invisible.
