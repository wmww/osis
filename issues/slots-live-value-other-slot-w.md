# A Slots position's valued W in an unchosen slot is no live value
> Summary: spec/crdt.md §4.3 says a `Slots` position holds a live value iff its chosen slot does, so the position's one presence write (§7), valued, in a slot that is not chosen counts for nothing: an empty map `W` t3, an entry added t4 and removed t6, and an unseen empty list `W` t5 read present but hold no live value (the map's `W` is beaten by the list's). Matters only under a value-less creation (§4.7: an expired entry or list element creation is live only while its content holds a live value). Decide whether the position's `W` counts whichever slot holds it.
> Priority: low
> Tags: crdt

Same outcome when the chosen slot never had a `W` (created with content). Probe: `Fragment::live_value` on `join(map, list)` as above gives false, `present` true.
