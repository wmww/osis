# The account's sync record is read whole per write
> Summary: Each write to `kept^.0` on D (an accept, a recorded secret, a lowering) decodes the whole map (`records::observe`: `Fragment::read`, then compares every entry): O(things kept × epochs recorded) per write, where the change is one thing's entry.
> Priority: low
> Tags: engine, performance

- Writes are rare (one per accept and per sync epoch recorded per thing), and nothing hot reads the map: sync reads the per-thing `sync_records` view. A node keeping 10^4 things unread over many rotations pays it on every rotation of any of them.
- Fix: derive from the changed map keys only (the write's path ops name them; a merged remote commit's parts too), or split the record per thing (one aspect per kept thing on D is not possible today: an aspect lives on its thing).
