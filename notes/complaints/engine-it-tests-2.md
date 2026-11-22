# engine-it-tests-2
> Summary: footguns met continuing the engine integration test consolidation.

- Caching a world can break a test that passes built fresh: a `LocalPeer::copy` of `two_paths_world` misses a waiting split path's wake (issues/copied-engine-misses-path-wake.md). When a newly cached setup fails one test, rerun it with `lp.copy()` on the fresh build before suspecting the edit.
- A `LocalPeer::cached` key reused for a different value type (validity's `two_paths_world` key held the split pair while the world itself was cached): give each cached builder its own key.
- A helper returning `impl Fn` where the old closure was `Copy` (captured only references) fails to build at every second use (E0382): add `+ Copy` to the return type.
- Replacing a setup's destructure with a helper's return leaves names unused (20 warnings in flows): fix them from the build log's `-->` locations by script, then rebuild.
