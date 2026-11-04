# A commit waits for a dropped part when nothing later on its aspect is left
> Summary: Atomic apply releases a missing part under keep at most 0 after replaced only once a later commit on its aspect is held. If the part's killer has itself left with nothing later (it expired or was purged, or was deleted as invalid), a fresh node holds no such commit and the commit waits until the aspect's next write or snapshot: its other parts read old, a lasting header shows no tombstone, and the node's view stays unsettled. Rare and self-healing; accepted for now.
> Tags: engine, sync

Repro sketch: c1 = {m (at most 0), k}; c2 = {m with `expires`}. c1's `m` body drops at the kill and is deleted at hosts; at T hosts delete c2. A fresh node gets only c1's `k` blob: nothing on `m` is left to show that c1's part could have gone (`apply::at_most_bound`), so c1 pends and `k` reads old there.

A lasting header reaches this through a host with no body left: a purge request whose one delta is that `m` stays under its labels as a header-only blob, and it and the commit it names wait (`tombstone::a_lasting_request_waits_when_its_killer_left_spec_commits_4`).

A write's own commit is stamped with it, so a nested write stamped after an entry's removal stays live (the entry returns). A killer stamped earlier takes a copy: a snapshot of a write removed before it. Its one delta dead, its body goes everywhere and it is no lasting header (a snapshot carries no request), so nothing of it reaches a later node; only a bare header handed over by hand waits, holding back nothing (`timed_dead::snapshot_dead_by_earlier_removal_leaves_no_wait_spec_commits_4`). A later seed of `sessions::gap_cover_large` that pends on a commit with a body left is not known to be this issue: look at it.

Closing it needs one of: releasing on the class alone (a live part on its way never waits: rejected, spec/commits.md §4), or a record at hosts or in a header that a body left (a blob or commit per drop, which keep at most 0 exists to avoid).
