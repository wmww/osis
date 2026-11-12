# Per-commit chunk limit is about 95 GB, requirements say 140
> Summary: Chunk list entries carry a 16-byte link blind (spec/wire.md §4), about 55 B each, so one `MAX_LIST_BYTES` (64 MiB) list holds about 1.2 million blobs, about 95 GB of chunks; spec/requirements.md still says about 140 GB. The same bound now caps what one aspect's durable compaction snapshot can link.
> Priority: normal
> Tags: spec, tess-call

- Options: (a) requirements text to about 95 GB; (b) `MAX_LIST_BYTES` to 96 MiB, keeping 140 GB, which also moves the frontier limit (spec/requirements.md Cost, about 1.9 million writes) to about 2.9 million; (c) leave both and accept the mismatch until stability.
- Snapshot side: an aspect linking more blobs than one list holds cannot be compacted; `Engine::compactions` returns the snapshot's build error, which also skips every other aspect due that step. Reaching it takes a snapshot cost above 64 MiB of listing against twice that in held bodies, so it is far off, but it should be a stated limit or a skip, not an error.
