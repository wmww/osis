# An `until` passing tells no roster event
> Summary: An edge's `until` passing changes what a roster reads with no commit; the engine queued `Event::Roster` for such a thing when its time came (a work list of timed things, gone with the lost-access list). Nothing tells it now, so a watcher of a roster (osis `watch`) sees the change only with the next event touching that thing.
> Priority: normal
> Tags: engine

The lost-access drop is derived (notes/engine-lost-access.md, The drop) and reads the memo clock up to the next `until` of held actors only. A fix that keeps one mechanism: the watch layer (or the engine's event queue) follows the memo clock up to each watched roster's next `until` (`rotation::lost::next_until`) and tells the roster then.
