# A sync-alone holder's removal hands its readers headers
> Summary: once H (holding sync alone on X) is removed, every copy of H's edge piece on X goes with its header: the removal as a `grant@~0` fire (`deliver_copy`), and H's key part (`edge_pieces_into`, by the roster now) cuts the removal and the earlier grant and `sync.0` writes as certificate copies, so H's readers learn the grant's and remover's signers and paths (spec/sync-ids.md §2 What a sync holder learns). Role changes travel carries the removal alike.
> Priority: normal
> Tags: security, engine, permissions

- Seen: in `flows::tests_delivery`'s `sync_holder` world with peer 0 reading T, `certificates(&t)` at peer 0 names no commit on G before G's admin removes T, and three after (the removal, the grant, a `sync.0` write), each with its header.
- Not a drop-in sealed sync copy: a removal's piece boxes nothing, so as a copy it names no holder (`Unread::holders` counts boxes alone) but takes nothing away either: the grant's copy still counts, so H's readers would go on syncing X as H's. The copies need a way to tell a removal (say, the holder's box absent from a newer epoch a step bears), and then H's whole edge piece goes as copies whatever H's role now: `edge_pieces_into` would judge sync alone by the highest role H's held edge writes on X gave, not the roster.
- Sites marked Interim: `inbox::deliver_copy`, `certs::edge_pieces_into`.
