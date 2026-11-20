# blob-wait-review
> Summary: Mishaps met reviewing keyed blob waits.

- `put_blobs`'s fault positions: a failure at the last page's later writes (its round's) returns Ok and leaves a reload owed; with `blob_wants` no longer a transaction nothing in a test reloads unless it runs one (node-sync's step does, `engine_reloaded`). A test that only asks `blob_wants` after a fault sees a commit stuck that production would recover.
- Mutating by an env var read at the site (`if std::env::var("MUT").is_err()`) let one build serve several mutation runs.
