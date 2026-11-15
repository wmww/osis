# fathom-review-14
- The brief named two shas in no ref (cee0dfbaf, 1a06d1dd8); found the work as d732a2178 (SetFollow) and abb6926cb (join-post) by message.
- Engine-only tests seal nothing at commit: a test of blob rows must `seal_body` first (`commit_blobs` is empty otherwise).
