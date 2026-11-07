# A removal's frontier of any size
> Summary: Tess: drop the ~1.9M-commit kick limit (frontier as a linked header list capped at `MAX_LIST_BYTES`) by reusing the paging large deltas already have; no new concept. Cost stays one 32 B ID per kept write (requirements Cost). Only if it reuses existing infrastructure; a rare edge case, not a project.
> Priority: low
> Tags: permissions, wire, node
