# rotation-tests-2
> Summary: footguns met consolidating the remaining rotation unit tests.

- A cached world dropped a thread-local beside it: tests_signing's `setup_head` reads `SETUP_HEADS`, filled only when `world()` hands out a copy, so a cache built on top of `world()` (on whichever thread built it first) must store the head and set it again on every copy (`world_then`). Look for thread-locals next to a setup before caching on top of it.
- `osis_base::copying::cached` in a test module under `src/` fails policy (a world-copy hook outside tests); a world holding peers beside non-`Clone` state goes through `LocalPeer::cached_world`.
- A python anchor copied from a wrapped comment missed its `// ` continuation prefix and failed its count assert after an earlier file in the same script was already written: one file per script, or assert every anchor before writing any.
