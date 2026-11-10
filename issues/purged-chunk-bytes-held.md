# Purged chunks' bytes are held and served until every host deletes them
> Summary: A node keeps (or fetches back) the bytes of a chunk of a dropped delta while any label entry names it, only for the prefix salt its delete-key signature needs (`forget_chunk`, `chunk_delete`); flushed bytes are logged Added, so co-readers can pull purged values from the node until the hosts delete them. A writer's delete of a chunk it re-recorded from its tombstone (`host_holds`) fetches the bytes back past the tombstone for the same reason. Rule that avoids it: the delete needs only the salt.
> Priority: normal
> Tags: node, sync, security, retention

## Why it matters
spec/commits.md §5: dropping a body destroys every local copy. A non-admin purger (no label delete key) holds the purged chunk's ciphertext while hosts hold it, and serves it to co-readers through its log; for a chunk it never held it fetches it first. The tombstone's "bytes this node asked for pass" (inbound `log_events`) is the same need surfacing as a tombstone exception.

## Direction
A chunk entry keeps its prefix salt (as `Kind::Commit` keeps `salt`), taken when its bytes are first here; the bytes go with the purge like any dropped body's. A fetch made only for a delete reads the salt from the reply and stores nothing (no entry change, no log). Then the tombstone keeps every identical blob out with no exception, and `forget_chunk`'s "while named" wait goes.
