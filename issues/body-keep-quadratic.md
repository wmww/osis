# A body's must-hold judgment is quadratic in its parts
> Summary: node-sync's `must_hold` asks `Engine::body_keep` once per part of a body, and each call reads the deaths of every part of that body (`retention::deaths_of` over `body_class`'s holders, one store lookup each): parts² death lookups per body per pass, even for parts with no relative bound (which never get death records). A commit of 800 aspects in one body cost about 15 s per test.
> Tags: node, engine, performance

`SyncEngine::must_hold` (core/node/src/sync/pass/bodies.rs) → `part_kept` per part → `Engine::body_keep` → `retention::bounds::body_keep` → `deaths_of` → `class_deaths`: a `Transaction::death` lookup per holder of the body. With n parts sharing one body that is n² lookups per judged body, per pass (each lookup decodes store pages afresh). Measured: `hostile_host::linked_header_prefix_checked_spec_commits_4` with 800 aspects in one commit spent 89% of 24 CPU-s there; its tests now use 135 long-keyed aspects instead (`common::link_aspects`).

Cheap cures, either: compute the body's deaths once per body in `must_hold` (they are the same for every part of the body: `class_deaths` ranges over the same holders); skip the lookups when no holder has a relative bound (`retention::bounded`: only those get death records, spec/commits.md §5).
