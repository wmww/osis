# Two kinds of hidden write the compaction sweep does not reach
> Summary: `Fragment::sweep` (spec/sync.md §7) takes records with their own reset or a creation held value-less. Two honest flows keep bytes: an edit newer than a parent's reset (a `replace` of the map: the record looks like a partial receipt, no reset of its own) and a payload edit of a non-current enum case (nested registers carry no reset). Each needs a concurrent edit; reads never show them.
> Tags: security, crdt, engine

For the first, the node could treat a record as hidden when it holds the header of the delta owning its dot, valid and applied; a record whose creator is only invalid for now must stay. For the second, a case write again at a new reset would sweep it, but rewrites the live payload.
