# An undelete's copy of a purged char may stay on disk
> Summary: Unverified (leftover-bodies review 3): a whole undelete delta keeps its own copy of the original element's char; purging the original strips only held snapshots (`purge_one`), so the undelete's copy may keep the purged value on disk. Predates leftover-bodies.
> Tags: security, engine, crdt

Check: write a text char, delete it, undelete it (spec/crdt.md §5.7: the undelete may carry the char), purge the original write; run the forensic attack (`osis_store::attack`) over the store. If the char is found, the purge must also strip (leave as leftover) every held body carrying a copy of a purged write, which the one rebuild path (item 274) should make simple: the copy is a write under the purged dot.
