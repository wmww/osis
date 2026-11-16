# keel-review-a
- A test that picks "the last created thing" by tid order (`w.created.keys().last()`) silently changes subject when any encoding feeding the tid changes (here the creation record's weak tag): perm `scale::demotion_scope_walks_at_most_the_history` broke on a wire change it has nothing to do with. Pick test subjects by construction.
