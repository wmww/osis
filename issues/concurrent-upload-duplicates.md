# Writers online together upload the same things twice
> Summary: When several writers of a label hold the same new commits or see the same reader deposit at the same moment, each uploads its own copy (a fresh encryption of the commit, or the deposit re-sent stamped). The extra copies are deleted later, so nothing is lost, but upload bytes grow with the number of writers online at once: a reader's card or invite deposit in a group of 200 online writers could be sent up to 200 times.
> Tags: performance, sync, node

Seen in osis-node `sync_more.rs` (`Net::group` hands every member the admin's commits directly, then all start together; `OSIS_TRACE_UPLOADS=1`): the writer re-encrypts and uploads every closure body the admin uploads in the same round, and both writers promote each of the reader's deposits. Not seen in the chat cost test (its members join one by one).

- Closure bodies: `pass` uploads a must-hold body unless an entry of it is known under the label; two writers holding the same new commit before either saw the other's entry both upload. The duplicate with the higher blob ID is judged must-not-hold and deleted (spec/sync.md §7), so the cost is one upload and one delete per extra writer.
- Promotions (`SyncEngine::promote`): every writer re-uploads an unstamped deposit it sees; the server keeps one entry (same blob ID), the bytes are sent once per writer.
- Possible fix: the same settle idea as certificates (`SETTLE_MS` in `pass.rs`): a writer that is not the commit's author (or the deposit's) waits a moment before uploading or promoting another node's entry, and skips it if one arrived meanwhile; or a deterministic choice of which writer promotes (the lowest node tid among those with a recent heartbeat). Both trade a few seconds of latency for bytes.
