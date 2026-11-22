# Complaints: sync-diff-2
> Summary: Shrinking without OSIS_SHRINK_MATCH drifts to another class; hand-forcing a fetch order in a World has no lever; tools/bin-at rebuilds per probe.

- `OSIS_SYNC_SHRINK=1` on seed 3994064562 shrank to the other open class's message (must-hold bodies) unless `OSIS_SHRINK_MATCH` was set; the drift turned out useful (same cause, a faultless 7-step script failing 10 of 50 worlds), but a brief should say to set the match.
- No World lever forces "T's content entries before its keysets" (a fetch split over two sources): partitions, `Lie::Withhold` and by-hand `Store::log` + `Engine::open_entry` all left the part pending, since a pass end is what counts it never received. The reproducer went to the engine (`LocalPeer`), where `Engine::seal_body` + `open_entry` give a blob the engine notes (a `LocalPeer::sealed` package notes none, so it cannot test redelivery).
- Old-vs-new for a new test needs `tools/bin-at REV --patch` per edit of the test: about a minute each, many rounds while finding a reproducer.
