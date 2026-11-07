# Newest demotion's frontier for writes ordered after it
> Summary: spec/permissions.md §5.2 says a demotion's frontier saves only writes ordered before it, but perm (`delta_valid_uncached`), roles-model and held-model also accept the newest demotion's frontier for a write ordered after it (clock skew). State it in spec or drop it from all three. Also roles-model `addenda::PLAN` is still `Rerem::Newest` (stale since every demotion's frontier counts): set `Rerem::Any` and rerun its searches.
> Priority: normal
> Tags: permissions, spec, tests
