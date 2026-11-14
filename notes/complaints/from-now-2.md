# from-now-2
- Each planted-fault probe of an osis-engine lib test rebuilds the engine's test binary (about 2 min at load 20): six probes cost more than the tests. A per-fault env switch would not be better (code paths in tests); batching the probes into one background script helped.
- `held_parts` lists versions too ("listed or not"): a test of what a node lists must filter by `listed_at`; easy to assert the wrong thing first.
- No end-to-end check of a grant without history exists above the engine (the sync side is not built): an osis-chat test of it reads nothing yet, so it is committed ignored.
