# big_map_apply_memory peak doubled after no-misstates
> Summary: `big_map_apply_memory` at 200k keys peaked at about +547 MiB on branch no-misstates against +277 MiB on main before it; not from its last commit, maybe allocator noise. Measure main before/after the merge (release, alone) and find the cause if real.
> Priority: low
> Tags: engine, performance
