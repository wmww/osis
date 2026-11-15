# fathom-review-14
- The brief named two shas in no ref (cee0dfbaf, 1a06d1dd8); found the work as d732a2178 (SetFollow) and abb6926cb (join-post) by message.
- Engine-only tests seal nothing at commit: a test of blob rows must `seal_body` first (`commit_blobs` is empty otherwise).
- `ManualNet::run` moves the clock to each wake up to an hour ahead, so a `PASS_WAIT_MS` wait ends inside one `run`: assert "still waiting" before running the net, not after.
- A setting-wait test that ingests a thing's commits one by one sees the thing uncarried (so not waited for) until its listing commit lands: ingest the listing in the same or an earlier commit.
