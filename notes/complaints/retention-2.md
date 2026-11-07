# retention-2
- `MemoryBackend::history()` records nothing unless `record_history()` is called on the backend; `LocalPeer`'s `net()` peers do not, so a byte measure reads 0 silently.
- A write is not identified by its dot or stamp (a map entry's creation and its values share one): "the state lacks a write of the body" by dot missed every overwritten map value; the crdt's death reports are the reliable test.
- Order-harness regression tests built from played histories break when playing changes the commit list (a writer now writes covers while playing): hand-picked order indexes in them go stale silently.
- Several tier-1 tests asserted mechanism (timers, carriers, `due_live_drops`) rather than what a user sees; each had to be read to tell a premise gone from a regression.
