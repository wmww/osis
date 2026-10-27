# Deaths replay costs the aspect's history per late delta
> Summary: On an aspect with a relative keep bound (every `/members`, any keep-at-least or keep-at-most content aspect), each delta arriving out of `(ts, ID)` order, each snapshot and each validity flip re-joins every held body and the whole state (`retention::rejudge_deaths`): O(aspect history) per such delta, against spec/requirements.md Scale.
> Tags: node, retention, performance

Measured (release, a set of N one-element commits, then 5 deltas by another writer older than all of them, each applied alone): N = 3000, unbounded set 1.3-2.2 ms per late delta, keep-at-least set 140-190 ms (about 55 µs per held body, linear); an in-order local write 1.5 / 3.1 ms. Concurrent writers make about half of all received deltas late, so a bounded aspect of 10^5 commits costs seconds per received change; a node syncing a large `/members` history out of order pays O(n²).

Before: only keep-at-most aspects paid, joining the delta with the bodies under a pending keep-at-most timer (few) plus a scan of every timer record.

Fix direction: replay only from the late delta's position (needs the state as of that position, or per-write deaths: issues/deaths-dropped-superseder.md has the same root), or batch replays per transaction and per sync batch (one replay per aspect per ingested batch instead of per delta).
