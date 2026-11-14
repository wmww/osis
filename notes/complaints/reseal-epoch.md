# reseal-epoch
- A write transaction inside `Engine::open_commit` (to record openings) changed node-sync behaviour far away (resnapshots, purge falls, nodelog convergence): `Engine::run`'s end runs a dozen follow-ups. Engine state that must not settle anything has to ride in `Core` until a transaction that writes the commit anyway.
- Old node-sync (frozen) passes only unopened sections to `Engine::seal` and ingests plaintext, so the engine cannot see which epoch a body came under without recording it at open; much of the design cost here was working around a caller I could not change.
- A fresh seal copying a held section verbatim first resurrected purged content (the held part was a leftover): verbatim needs "the section carries what I hold".
- Reproducer briefs that say "deliver everything of R's" with LocalPeer's plain `sync` bypass sections entirely; tests of what was opened under which epoch must deliver the write as its sealed entry.
