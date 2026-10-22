# Nodes on either side of a keep-at-least bound delete and re-place each other's projections
> Summary: Two right holders whose corrected clocks straddle a body's keep-at-least bound disagree on whether a covered delta is dropped: the one past the bound deletes the other's projection holding it (`Why::Dropped`), the other re-places it as must-hold; delete/re-place churn for as long as the skew.
> Tags: sync, node, retention

Not seen in a sweep (the sim's schemas have no keep-at-least bounds); follows from the compaction fix on branch sim-bugs (notes/sync.md, compaction 2887). Bounded by the corrected clock skew (spec/sync.md §6) once both nodes pass the bound and judge the snapshot again.

## Technical details
`drop_covered` (sync/local.rs) drops a covered body once `body_keep().at_least <= now`; `judge` (sync/pass.rs) then marks another node's projection holding the dropped part must-not-hold. Structural fix: judge such deletes on the overlap of what both dropped (a compaction-dropped part that another node's projection still holds is not a reason to delete it), and leave the superset to the strict-subset rule once every holder dropped the part.
