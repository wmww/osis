# Taking up a link key re-judges every local-part edge
> Summary: engine `closure::a_take_up_costs_what_the_opener_opens_*` counts 44 closure edges judged at n and 404 at 10n (run alone, the same at the base before opening by entries): every local-part edge reads the whole link-key set, so taking up one link key re-judges every edge; options below.
> Priority: normal
> Tags: engine

The test passed at the base only by its draws: its count also shifts inside the full suite (its cause breakdown reads process-wide debug state), which hid the growth. Fix the cost, then make the count independent of what else ran.

Options:
- Give each local-part edge a per-target view of which own things hold something on it, so a new link key moves only the edges onto its targets.
- Make each link key its own unit in the closure walk, so its take-up touches its unit alone.
