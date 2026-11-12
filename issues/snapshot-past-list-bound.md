# An aspect too large to compact makes compaction error
> Summary: A durable compaction snapshot links every blob its aspect's value links, in one `MAX_LIST_BYTES` (64 MiB) list (about 1.2 million blobs, about 95 GB, the same bound as a commit's chunks, spec/requirements.md). An aspect linking more cannot be compacted; `Engine::compactions` then returns the snapshot's build error, which also skips every other aspect due that step.
> Priority: low
> Tags: engine, retention

- Reaching it takes a snapshot cost above 64 MiB of listing against twice that in held bodies, so it is far off; it should be a stated limit with that aspect skipped (its other aspects still compacted), not an error for the whole step.
