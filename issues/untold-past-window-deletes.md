# An untold node past a purge's window empties instead of leaving
> Summary: osis-sync `judge::doom` reads a destroyed thing's window from each request's `expires`; a request without one leaves the engine's `Destruction::requests` at the end of its window, so an untold node then reads "no request" as a destruction by expiry alone, is told by vacuity and deletes at its sources, where spec/sync-judgement.md §5 Untold forgets deleting nothing.
> Priority: low
> Tags: sync, engine

- A told node is unaffected: told is sticky, and past the window it closes and forgets as §5 says.
- Fix shape: the engine tells doom a window-passed request apart from expiry alone (the destroyed-for-good mark, spec/commits.md §5), and doom ends the window by "kept no more" alone, not by `expires`. A read restart loses `told`, so a told node restarting past the window would then leave as untold: check that against core/test/tla/net/NetDestroy.tla (`DN_untold`, `KLeft`) first.
- Test to write: the destruction world of core/sync/tests/it/destruction.rs with node 2 partitioned for the whole window, healed past it: no Delete from node 2.
