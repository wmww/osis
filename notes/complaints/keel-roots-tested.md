# keel-roots-tested
- `Engine::released` dropped a retained copy's content (its `forget::Scope::Local` took every released thing), though spec/sync-set.md §3 excepts a copy: no test released a copy, since engine tests call `settle_needs` and `released` only where they mean to. Found only by writing the reproducer for the copy root.
- `keep_bearer` had no caller anywhere (contact cards became redeems), yet its records, index, drop rule, retention root and notes stayed; a grep for callers of each `pub fn` a root reads would have found it at once.
