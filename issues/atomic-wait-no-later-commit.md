# A commit waits for a dropped part when nothing later on its aspect is left
> Summary: Atomic apply releases a missing part under a relative keep at most only once a later commit on its aspect is held. If the part's killer has itself left with nothing later (it expired or was purged, or was deleted as invalid), or was stamped before the part (a write nested in an entry a slower clock's commit removed), a fresh node holds no such commit and the commit waits until the aspect's next write or snapshot. Rare and self-healing; accepted for now.
> Tags: engine, sync

Repro sketch: c1 = {m (at most 0), k}; c2 = {m with `expires`}. c1's `m` body drops at the kill and is deleted at hosts; at T hosts delete c2. A fresh node gets only c1's `k` blob: nothing on `m` is left to show that c1's part could have gone (`apply::at_most_bound`), so c1 pends and `k` reads old there. Killer stamped earlier: `waits::dead_part_with_earlier_killer_waits_for_next_write_spec_commits_4`.

Closing it needs one of: releasing on the class alone (a live part on its way never waits: rejected, spec/commits.md §4), or a record at hosts or in a header that a body left (a blob or commit per drop, which keep at most 0 exists to avoid).
