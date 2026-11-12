# Three kinds of hidden write the compaction sweep does not reach
> Summary: `Fragment::sweep` (spec/sync.md §7) takes records with their own reset or a creation held value-less. Three honest flows keep bytes: an edit newer than a parent's reset (a `replace` of the map: the record looks like a partial receipt, no reset of its own), a payload edit of a non-current enum case (nested registers carry no reset), and an edit nested in a record whose creation is invalid (un-merge keeps it, spec/crdt.md §4.6; the record looks like a partial receipt too). Each needs a concurrent edit or a removal; reads never show them.
> Priority: normal
> Tags: security, crdt, engine

For the first, the node could treat a record as hidden when it holds the header of the delta carrying its dot, valid and applied. The third is the same record shape with the creating delta held invalid: it must stay while that delta may turn valid again (a re-grant). For the second, a case write again at a new reset would sweep it, but rewrites the live payload.

One limit from reading the code, not run: a sweep's content-less list records count toward `MAX_DELTA_BARE` (2^18 per writer delta, spec/crdt.md §3.3 rule 7). A view with more hidden elements than that writes a delta receivers refuse. It needs 2^18 hidden edits between compactions.
