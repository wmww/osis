# sync-removed-write
- Shrinking a faulty full-size seed (`OSIS_SYNC_SHRINK=1`) took about 8 minutes each; two in sequence outran several `claudewait` rounds.
- Reading a long spec range with `sed` through Bash spilled to a persisted-output file twice (40 KB); `Read` with offset/limit was the way through.
- The differential's failure says only "reads unlike the reference"; finding that the engine threw the commit out (`Ingested::Awaits`) took temporary prints in `open_entry_now`. A trace of each entry's `Opened` outcome per node would have shown it at once.
