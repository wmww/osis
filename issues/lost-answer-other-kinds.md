# A lost upload answer leaves non-commit entries at the host
> Summary: A node's tombstone keeps the kind only of a commit entry that is not a certificate copy (`tomb_kinds`), so a host announcing it again gets it deleted there. Chunk entries of dropped deltas and the linked blobs of certificate copies that a node removes locally (`local_deletions`) keep no kind: if the host took their upload and its answer was lost with the connection, the host's announcement is ignored and that host keeps the copy unless another right holder deletes it there. One copy per such event (purge or copy removal racing a dropped connection); found by reading (own-placed review).
> Priority: low
> Tags: node, sync, growth

## Why
`State::remove_entry` stores a kind only for `Kind::Commit` entries without `cert`; `log_events` records a tombstoned announcement as present only when a kind is stored. While the upload is unanswered on a live connection `held_elsewhere` keeps such entries (its in-flight check), so only the lost-answer case leaks.

## Direction
One mechanism would be: a host reporting an entry this node tombstoned (an announcement or an OK upload answer) records it quietly as present there, whatever its kind, and the host pass judges it as any present entry. That would also let `held_elsewhere` drop its in-flight check (a mid-upload drop then goes by the same rule). It needs the host pass to judge chunk and linked-blob entries from presence alone (`chunk_entries`/`dropped_chunks` and `copy_links` find candidates from commits still known), and a kept presence row with no rule to delete it would be a node-side leak instead.
