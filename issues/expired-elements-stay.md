# An expired set element stays in its set's snapshots
> Summary: A strong (or any set element) added by an expiring write stays in the set's state and every snapshot of it as a value-less record, about 60 B each, for good: a disappearing message held from its channel (or D) grows the holder by that per message ever sent. The thing itself leaves no row.
> Priority: normal
> Tags: crdt, engine, retention

- Seen in sync `growth::expired_things_return_storage_to_a_fresh_nodes_spec_commits_5`: about 62 B per expired strong in D's `holds.0` snapshot rows (`c/`) and its blobs, linear in rounds; the test allows it as two removals' tombstones (marked Interim).
- Why it stays: expiry keeps a delta's value-carrying writes value-less (spec/crdt.md §4.7, Leftovers at expiry), and a set element's creation is its value, so the record has a write and never goes (notes/crdt.md: every record with no write goes). A removal prunes it; nothing prunes an expired one.
- Unlike a list element (an anchor for live neighbours: issues/eph-expired-anchors-fill-cap.md) a set element places nothing and nothing writes into it, so the lattice may not need the record: what it would change is how a removal of that dot, or a late copy of the add (past its expiry, it joins value-less), reads, which shows nothing either way (notes/crdt.md, No set/bag tombstone GC, is about removals of live adds). Check that with crdt-model before dropping it at expiry.
