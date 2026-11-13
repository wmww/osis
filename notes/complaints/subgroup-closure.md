# subgroup-closure
- About ten call sites (labeling, marks, sources, share, signals, lifetimes, `syncs`, `carried`, `require_synced`) each spelled "groups carrying t" as `t == g || groups_of(t).contains(g)` by hand; one helper (`Engine::enclosing`) would have made the membership/closure split a one-line change.
