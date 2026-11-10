# A commit pending for header pages that turns unjudgeable stays pending
> Summary: A commit whose linked header list waits for pages (`Reason::WaitBlobs`) is pending; once the pages arrive and every part it holds is unjudgeable, `examine` throws it out, but its stored pending copy stays (bytes kept against spec/commits.md §4, under a stale `WaitBlobs` reason) because node-sync holds its entry as a commit and would never fetch it again.
> Priority: low
> Tags: engine, node-sync

Every other path decides unjudgeability before any pending reason (`apply::examine`), so no pending commit is unjudgeable; this one cannot, as only the resolved header names the aspects. Reads still converge (the kept copy applies when the record comes). The fix: when a pending commit examines as unjudgeable, unpend it and tell node-sync (a `Wakes` field) to turn the commit's entries (`State::by_commit`) into `Kind::Awaits` (`mark_awaits`), and `LocalPeer` to keep the bytes as `Discarded`. Test: a commit with linked pages on a thing whose record is unknown, pages last.
